import os
import argparse
import tempfile
from ldap3 import Server, Connection, ALL, NTLM
from impacket.smbconnection import SMBConnection

DEFAULT_DC_POLICY_GUID = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
GPT_RELATIVE_PATH = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"

# Absolute well-known SIDs that LDAP often will not resolve to a sAMAccountName.
WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
}

# Domain-relative RIDs (matched against the trailing RID after LDAP/local lookup).
WELL_KNOWN_RIDS = {
    "512": "Domain Admins",
    "513": "Domain Users",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
}

# Principals that mean "essentially any authenticated account in the domain".
BROAD_PRINCIPALS = {"S-1-5-11"}  # Authenticated Users
BROAD_RIDS = {"513"}            # Domain Users


def build_base_dn(domain):
    return "DC=" + domain.replace(".", ",DC=")


def parse_hashes(hashes):
    """Split LM:NT (or :NT) into (lmhash, nthash). Returns ('', '') if none."""
    if not hashes:
        return "", ""
    if ":" in hashes:
        lm, nt = hashes.split(":", 1)
    else:
        lm, nt = "", hashes
    return lm, nt


def ldap_connect(dc_ip, username, password, domain, lmhash, nthash):
    user = f"{domain}\\{username}"
    # ldap3 NTLM accepts a password OR an "LM:NT" hash string in the password field.
    secret = f"{lmhash}:{nthash}" if nthash else password
    server = Server(dc_ip, get_info=ALL)
    return Connection(server, user=user, password=secret,
                      authentication=NTLM, auto_bind=True)


def resolve_sids_ldap(conn, domain, sids):
    resolved = {}
    base_dn = build_base_dn(domain)
    for sid in sids:
        sid = sid.strip("*")
        if sid in WELL_KNOWN_SIDS:
            resolved[sid] = WELL_KNOWN_SIDS[sid]
            continue
        try:
            conn.search(search_base=base_dn,
                        search_filter=f"(objectSid={sid})",
                        attributes=["sAMAccountName"])
            if conn.entries:
                resolved[sid] = conn.entries[0].sAMAccountName.value
            else:
                rid = sid.rsplit("-", 1)[-1]
                resolved[sid] = WELL_KNOWN_RIDS.get(rid, "Not found")
        except Exception as e:
            resolved[sid] = f"Lookup error: {e}"
    return resolved


def get_machine_account_quota(conn, domain):
    """Read ms-DS-MachineAccountQuota off the domain NC head (default 10)."""
    try:
        conn.search(search_base=build_base_dn(domain),
                    search_filter="(objectClass=domain)",
                    attributes=["ms-DS-MachineAccountQuota"])
        if conn.entries:
            val = conn.entries[0]["ms-DS-MachineAccountQuota"].value
            if val is not None:
                return int(val)
    except Exception as e:
        print(f"[!] Failed to read ms-DS-MachineAccountQuota: {e}")
    return None


def connect_to_smb(dc_ip, username, password, domain, lmhash, nthash):
    try:
        conn = SMBConnection(dc_ip, dc_ip)
        conn.login(username, password, domain, lmhash, nthash)
        return conn
    except Exception as e:
        print(f"[!] Failed to connect to SMB: {e}")
        return None


def extract_sids_from_gpttmpl(conn, gpt_path):
    share = 'SYSVOL'
    fd, local_temp = tempfile.mkstemp()
    os.close(fd)

    try:
        with open(local_temp, 'wb') as f:
            conn.getFile(share, gpt_path, f.write)
    except Exception:
        os.remove(local_temp)
        return []  # File not found or access denied

    sids = []
    try:
        with open(local_temp, "r", encoding="utf-16") as gpo_file:
            gpo_lines = gpo_file.read().split("\n")
        for line in gpo_lines:
            if "SeMachineAccountPrivilege" in line and "=" in line:
                sid_line = line.split("=", 1)[1].strip()
                if not sid_line:
                    continue
                sids = [sid.strip() for sid in sid_line.split(",") if sid.strip()]
    except Exception as e:
        print(f"[!] Failed to parse {gpt_path}: {e}")
    finally:
        os.remove(local_temp)

    return sids


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Enumerate SeMachineAccountPrivilege (who can join machines to the "
                    "domain) from the Default Domain Controllers Policy, plus the "
                    "MachineAccountQuota that gates it.",
        epilog="Example:\n"
               "  %(prog)s -dc-ip 10.0.0.1 -d corp.local -u admin -p Passw0rd\n"
               "  %(prog)s -dc-ip 10.0.0.1 -d corp.local -u admin -H :aad3b435b51404ee...",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-dc-ip", required=True, help="Domain controller IP address")
    parser.add_argument("-d", "--domain", required=True, help="Domain name (e.g. corp.local)")
    parser.add_argument("-u", "--username", required=True, help="Username for auth")
    parser.add_argument("-p", "--password", default="", help="Password for auth")
    parser.add_argument("-H", "--hashes", metavar="LM:NT",
                        help="NTLM hashes for pass-the-hash (LM:NT or :NT)")
    return parser.parse_args()


def main():
    args = parse_arguments()

    if not args.password and not args.hashes:
        print("[!] Provide a password (-p) or hashes (-H).")
        return

    lmhash, nthash = parse_hashes(args.hashes)

    conn = connect_to_smb(args.dc_ip, args.username, args.password, args.domain, lmhash, nthash)
    if not conn:
        return

    gpt_path = f"/{args.domain}/Policies/{DEFAULT_DC_POLICY_GUID}/{GPT_RELATIVE_PATH}"
    sids = extract_sids_from_gpttmpl(conn, gpt_path)

    if not sids:
        print("[!] No SeMachineAccountPrivilege entries found or GptTmpl.inf not present.")
        return

    # One LDAP bind reused for SID resolution and the MAQ lookup.
    ldap_conn = None
    try:
        ldap_conn = ldap_connect(args.dc_ip, args.username, args.password,
                                 args.domain, lmhash, nthash)
    except Exception as e:
        print(f"[!] LDAP bind failed (SID names/MAQ unavailable): {e}")

    resolved = resolve_sids_ldap(ldap_conn, args.domain, sids) if ldap_conn else {}
    maq = get_machine_account_quota(ldap_conn, args.domain) if ldap_conn else None

    print("[+] SeMachineAccountPrivilege holders in Default Domain Controllers Policy:")
    broad = False
    for sid in sids:
        sid = sid.strip("*")
        name = resolved.get(sid) or WELL_KNOWN_SIDS.get(sid, "Unknown")
        rid = sid.rsplit("-", 1)[-1]
        if sid in BROAD_PRINCIPALS or rid in BROAD_RIDS:
            broad = True
        print(f"    {sid} -> {name}")

    if maq is not None:
        print(f"[+] ms-DS-MachineAccountQuota: {maq}")

    # Exploitability verdict.
    if maq == 0:
        print("[*] MachineAccountQuota is 0 -> privilege grants no joins regardless of holders.")
    elif broad and (maq is None or maq > 0):
        print("[!] Broad principal (Authenticated/Domain Users) holds the privilege "
              "with a non-zero quota -> any domain user can create machine accounts "
              "(RBCD / noPac territory).")


if __name__ == "__main__":
    main()
