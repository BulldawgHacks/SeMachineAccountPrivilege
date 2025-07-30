import os
import argparse
import tempfile
from ldap3 import Server, Connection, ALL, NTLM
import base64
from impacket.smbconnection import SMBConnection

DEFAULT_DC_POLICY_GUID = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
GPT_RELATIVE_PATH = f"Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"

def resolve_sids_ldap(dc_ip, username, password, domain, sids):
    resolved = {}
    user = f"{domain}\\{username}"

    try:
        server = Server(dc_ip, get_info=ALL)
        conn = Connection(server, user=user, password=password, authentication=NTLM, auto_bind=True)
        for sid in sids:
            sid = sid.strip("*")
            search_filter = f"(objectSid={sid})"
            conn.search(search_base=f"DC={domain.replace('.', ',DC=')}",
                        search_filter=search_filter,
                        attributes=["sAMAccountName"])
            if conn.entries:
                entry = conn.entries[0]
                name = entry.sAMAccountName.value
                resolved[sid] = name
            else:
                resolved[sid] = "Not found"

    except Exception as e:
        print(f"[!] LDAP SID resolution failed: {e}")
    return resolved


def connect_to_smb(dc_ip, username, password, domain=''):
    try:
        conn = SMBConnection(dc_ip, dc_ip)
        conn.login(username, password, domain)
        return conn
    except Exception as e:
        print(f"[!] Failed to connect to SMB: {e}")
        return None

def extract_sids_from_gpttmpl(conn, gpt_path):
    share = 'SYSVOL'
    local_temp = tempfile.mktemp()

    try:
        with open(local_temp, 'wb') as f:
            conn.getFile(share, gpt_path, f.write)
    except Exception as e:
        return []  # File not found or access denied

    sids = []
    try:
        with open(local_temp, "r", encoding="utf-16") as gpo_file:
            gpo_lines = gpo_file.read().split("\n")
        for line in gpo_lines:
            if "SeMachineAccountPrivilege" in line:
                sid_line = line.split("=")[1].strip()
                if "," in sid_line:
                    sids = [sid.strip() for sid in sid_line.split(",")]
                else:
                    sids.append(sid_line)
    except Exception as e:
        print(f"[!] Failed to parse {gpt_path}: {e}")
    finally:
        os.remove(local_temp)

    return sids


def parse_arguments():
    parser = argparse.ArgumentParser(description="Extract SeMachineAccountPrivilege from Default Domain Controllers Policy.")
    parser.add_argument("--dc-ip", required=True, help="Domain controller IP address")
    parser.add_argument("--username", required=True, help="Username for SMB auth")
    parser.add_argument("--password", required=True, help="Password for SMB auth")
    parser.add_argument("--domain", required=True, help="Domain name")
    return parser.parse_args()


def main():
    args = parse_arguments()
    conn = connect_to_smb(args.dc_ip, args.username, args.password, args.domain)
    if not conn:
        return

    gpt_path = f"/{args.domain}/Policies/{DEFAULT_DC_POLICY_GUID}/{GPT_RELATIVE_PATH}"
    sids = extract_sids_from_gpttmpl(conn, gpt_path)

    if sids:
        print(f"[+] Found SeMachineAccountPrivilege in Default Domain Controllers Policy:")
        resolved = resolve_sids_ldap(args.dc_ip, args.username, args.password, args.domain, sids)
        for sid in sids:
            sid = sid.strip("*")
            if sid == "S-1-5-11":
                name = "Authenticated Users"
            else:
                name = resolved.get(sid, "Unknown")
            print(f"    {sid} -> {name}")
    else:
        print("[!] No SeMachineAccountPrivilege entries found or GptTmpl.inf not present.")


if __name__ == "__main__":
    main()
