#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from enterprise_sim.crypto import ensure_idp_key
    from enterprise_sim.directory import bootstrap_directory
    from enterprise_sim.scim import provision
    from enterprise_sim.settings import ROOT
else:
    from .crypto import ensure_idp_key
    from .directory import bootstrap_directory
    from .scim import provision
    from .settings import ROOT

def main():
    ensure_idp_key()
    bootstrap_directory()
    # Ensure TokenSystem's own demo PKI exists, because federated tokens are
    # sender-constrained to the existing linux-laptop-001 certificate.
    pki_key = ROOT / "pki" / "linux-laptop-001.key.pem"
    if not pki_key.exists():
        subprocess.check_call([sys.executable, str(ROOT / "pki_bootstrap.py")], cwd=ROOT)
    for user in ("developer01", "security01", "contractor01"):
        provision(user)
    print("Enterprise simulation bootstrap complete.")
    print("Default user: developer01")
    print("Password: LabPassword!1")
    print("MFA OTP: 654321")
    print("Managed device: linux-laptop-001")
    print("Unmanaged device: personal-laptop-001")

if __name__ == "__main__":
    main()
