from pathlib import Path

ROOT = Path(__file__).resolve().parent
PKI = ROOT / "pki"
REQUIRED = [
    "ca.cert.pem", "ca.key.pem",
    "token-signing.cert.pem", "token-signing.key.pem",
    "linux-laptop-001.cert.pem", "linux-laptop-001.key.pem", "linux-laptop-001.p12",
    "agent-gpu-planner-dev.cert.pem", "agent-gpu-planner-dev.key.pem", "agent-gpu-planner-dev.p12",
]

def main():
    missing = [f for f in REQUIRED if not (PKI / f).exists()]
    if not missing:
        print("PKI files already exist and are ready for the demo.")
        print("Includes corporate CA, token signing cert, Linux device cert/key, agent cert/key, and PKCS#12 bundles.")
        print("PKCS#12 demo password: changeit")
        return
    raise SystemExit(
        "Missing PKI demo files: " + ", ".join(missing) +
        "\nRe-download the ZIP or restore the bundled pki/ folder. In production, these would be issued by corporate PKI."
    )

if __name__ == "__main__":
    main()
