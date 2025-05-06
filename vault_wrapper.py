import os
import subprocess
import getpass
import signal
import sys
import json

ENVIRONMENTS = {}
VAULT_BINARY = "D:\\vault\\vault.exe" if os.name == 'nt' else "vault"

namespace = ""
auth_mount_path = ""

def run_cmd(cmd):
    try:
        full_cmd = [VAULT_BINARY] + cmd[1:] if cmd[0] == "vault" else cmd
        env = os.environ.copy()
        if namespace:
            env["VAULT_NAMESPACE"] = namespace
        print(f"\n⏳ Running: {' '.join(full_cmd)} ... Please wait")
        result = subprocess.run(full_cmd, capture_output=True, text=True, env=env, timeout=15)
        output = result.stdout.strip()
        error = result.stderr.strip()
        if result.returncode != 0:
            print("❌ Vault command failed.")
            return f"❌ Vault Error (exit code {result.returncode}):\n{error or output}"
        print("✅ Done.")
        return output or error or "✅ Command executed, but no output returned."
    except subprocess.TimeoutExpired:
        return "⏱️ Command timed out. Please check Vault status, network, or auth settings."
    except Exception as e:
        return f"⚠️ Unexpected exception while running Vault command: {e}"

def detect_kv_version(mount_path):
    try:
        output = run_cmd(["vault", "read", f"sys/internal/ui/mounts/{mount_path.strip('/')}/"])
        if 'version:\"2\"' in output or 'version: 2' in output:
            return 2
        return 1
    except:
        return 1

def select_environment():
    print("Select Environment:")
    for key, (name, _) in ENVIRONMENTS.items():
        print(f"{key}) {name}")
    choice = input("(Enter number or name)> ").strip().lower()
    for key, (name, addr) in ENVIRONMENTS.items():
        if choice == key or choice == name.lower():
            os.environ['VAULT_ADDR'] = addr
            print(f"Selected {name} ({addr})")
            return True
    print("Invalid choice.")
    return False

def login():
    global namespace, auth_mount_path
    print("Choose auth method:")
    print("1) userpass")
    print("2) token")
    print("3) ldap")
    method = input("(Enter number or name)> ").strip().lower()

    if method in ["1", "userpass"]:
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        cmd = ["vault", "login", "-method=userpass", f"username={username}", f"password={password}"]
        print(run_cmd(cmd))
    elif method in ["2", "token"]:
        token = getpass.getpass("Enter Vault token: ")
        os.environ['VAULT_TOKEN'] = token
        print("Token set successfully.")
    elif method in ["3", "ldap"]:
        ns = input("Enter Vault namespace (leave blank for root): ").strip()
        namespace = ns
        ap = input("Enter auth mount path (leave blank for 'ldap'): ").strip()
        auth_mount_path = ap if ap else "ldap"
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        cmd = ["vault", "login", "-method=ldap"]
        if namespace:
            cmd.append(f"-ns={namespace}")
        if auth_mount_path:
            cmd.append(f"-path={auth_mount_path}")
        cmd += [f"username={username}", f"password={password}"]
        print(run_cmd(cmd))
    else:
        print("Invalid auth method.")

def get_dynamic_mounts():
    output = run_cmd(["vault", "secrets", "list", "-format=json"])
    try:
        mounts = json.loads(output)
        filtered = []
        for k in mounts.keys():
            if not k.startswith(("cubbyhole/", "identity/", "sys/")):
                caps = run_cmd(["vault", "token", "capabilities", k]).strip().lower()
                if any(cap in caps for cap in ["read", "list"]):
                    filtered.append(k.rstrip('/'))
        return filtered
    except json.JSONDecodeError:
        print("Unable to parse dynamic mounts. Showing fallback paths.")
        return []

def list_capabilities_summary():
    print("\n🔐 Fetching permissions based on mounted secret engines:")
    for path in get_dynamic_mounts():
        caps = run_cmd(["vault", "token", "capabilities", path]).strip()
        if not any(word in caps.lower() for word in ["deny", "permission denied"]):
            print(f"  📁 {path.ljust(25)} → {caps}")

def prompt_secret_path():
    mounts = get_dynamic_mounts()
    if not mounts:
        return input("Enter full secret path (e.g., secret/data/myapp/config): ").strip()
    print("Select base path:")
    for i, path in enumerate(mounts):
        print(f"{i+1}) {path}/")
    choice = input("Choose number or enter full path manually> ").strip()
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(mounts):
            base = mounts[idx].strip('/')
            print(f"\n📚 Listing existing secrets in '{base}/':")
            list_existing_secrets(f"{base}/")
            suffix = input("\nEnter remaining path after base (e.g., myapp/config or leave blank to exit): ").strip('/')
            return f"{base}/{suffix}" if suffix else f"{base}/"
    return choice.strip()

def list_existing_secrets(path):
    result = run_cmd(["vault", "kv", "list", path])
    print(result)

def read_secret():
    path = prompt_secret_path()
    if not path:
        return
    if path.endswith('/'):
        list_existing_secrets(path)
    else:
        print(run_cmd(["vault", "kv", "get", path]))

def write_secret():
    path = prompt_secret_path()
    if not path or path.endswith('/'):
        print("Invalid path to write. Please enter full secret path next time.")
        return
    print(f"\n📝 Preparing to write to: {path}")
    print("Enter key-value pairs (enter 'done' when finished):")
    data = []
    while True:
        key = input("  Key: ")
        if key.lower().strip() == 'done':
            break
        value = input("  Value: ")
        data.append(f"{key}={value}")
    if data:
        print(run_cmd(["vault", "kv", "put", path] + data))
    else:
        print("No data entered. Aborting write.")

def status():
    print(run_cmd(["vault", "status"]))

def handle_interrupt(signal_received, frame):
    print("\nInterrupted by user. Exiting gracefully.")
    sys.exit(0)

def main():
    global ENVIRONMENTS
    ENVIRONMENTS = {
        "1": ("Nonprod", "http://127.0.0.1:8200"),
        "2": ("Preprod", "http://127.0.0.1:8200"),
        "3": ("Prod", "http://127.0.0.1:8200"),
        "4": ("Learni", "http://127.0.0.1:8200")
    }
    signal.signal(signal.SIGINT, handle_interrupt)

    if not select_environment():
        return

    while True:
        print("""
Choose an action:
1) Login to Vault
2) What access do I have?
3) Browse & Read Secrets
4) Write a Secret
5) Vault Server Status
6) Quit
        """)
        choice = input("(Enter number or name)> ").strip().lower()
        if choice in ["1", "login"]:
            login()
        elif choice in ["2", "access"]:
            list_capabilities_summary()
        elif choice in ["3", "read", "browse"]:
            read_secret()
        elif choice in ["4", "write"]:
            write_secret()
        elif choice in ["5", "status"]:
            status()
        elif choice in ["6", "exit", "quit"]:
            print("👋 Exiting Vault Wrapper. See you soon!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
