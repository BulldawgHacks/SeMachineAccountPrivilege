import os
import argparse
import tempfile
from impacket.smbconnection import SMBConnection
from configparser import ConfigParser


DEFAULT_DC_POLICY_GUID = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
GPT_RELATIVE_PATH = f"Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"


def connect_to_smb(dc_ip, username, password, domain=''):
    try:
        conn = SMBConnection(dc_ip, dc_ip)
        conn.login(username, password, domain)
        return conn
    except Exception as e:
        print(f"[!] Failed to connect to SMB: {e}")
        return None


def find_domain_folder(conn):
    """Automatically find the domain folder inside SYSVOL"""
    try:
        share = 'SYSVOL'
        base_path = 'sysvol'
        for entry in conn.listPath(share, f'/{base_path}'):
            name = entry.get_longname()
            if name not in ('.', '..'):
                return name  # Assuming only one domain folder
    except Exception as e:
        print(f"[!] Error finding domain folder: {e}")
    return None


def extract_sids_from_gpttmpl(conn, gpt_path):
    share = 'SYSVOL'
    local_temp = tempfile.mktemp()

    try:
        with open(local_temp, 'wb') as f:
            conn.getFile(share, gpt_path, f.write)
    except Exception:
        return []  # File not found or access denied

    sids = []
    try:
        parser = ConfigParser(strict=False)
        parser.read(local_temp)
        if parser.has_section('Privilege Rights') and parser.has_option('Privilege Rights', 'SeMachineAccountPrivilege'):
            line = parser.get('Privilege Rights', 'SeMachineAccountPrivilege')
            sids = [sid.strip() for sid in line.split(',')]
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
    parser.add_argument("--domain", default='', help="Domain name (optional)")
    return parser.parse_args()


def main():
    args = parse_arguments()
    conn = connect_to_smb(args.dc_ip, args.username, args.password, args.domain)
    if not conn:
        return

    domain_folder = find_domain_folder(conn)
    if not domain_folder:
        print("[!] Could not find domain folder inside SYSVOL.")
        return

    gpt_path = f"/sysvol/{domain_folder}/Policies/{DEFAULT_DC_POLICY_GUID}/{GPT_RELATIVE_PATH}"
    sids = extract_sids_from_gpttmpl(conn, gpt_path)

    if sids:
        print(f"[+] Found SeMachineAccountPrivilege in Default Domain Controllers Policy:")
        for sid in sids:
            print(f"    {sid}")
    else:
        print("[!] No SeMachineAccountPrivilege entries found or GptTmpl.inf not present.")


if __name__ == "__main__":
    main()
