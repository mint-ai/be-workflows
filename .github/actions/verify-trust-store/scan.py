"""Scan a container filesystem (tar stream on stdin) for distrusted CA roots.

Looks at every file that looks like a trust store (PEM/DER bundles, Java
keystores) - not only the OS bundle, but also bundles vendored by language
packages (certifi, pip, HTTP client libraries, ...).
"""

import hashlib
import os
import re
import ssl
import subprocess
import sys
import tarfile
import tempfile

# SHA-256 fingerprints of roots that chain the compromised eMudhra intermediates.
# https://www.endorlabs.com/learn/emudhra-intermediate-ca-compromise-the-trust-stores-you-patched-and-the-ones-you-didnt-know-you-had
DISTRUSTED = {
    "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B": "emSign ECC Root CA - G3",
    "7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D": "emSign Root TLS CA - G3",
    "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5": "emSign Root CS CA - G3",
    "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4": "AAA Certificate Services",
}

PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
CERT_EXTS = (".pem", ".crt", ".cer", ".der")
KEYSTORE_EXTS = (".jks", ".p12", ".pfx", ".keystore", ".truststore")
NAME_HINTS = ("cacert", "ca-bundle", "ca_bundle", "ca-certificates", "truststore")
MAX_SIZE = 10 * 1024 * 1024
FOUND = 3  # exit code when a distrusted root is found


def is_candidate(path):
    name = os.path.basename(path).lower()
    return name.endswith(CERT_EXTS + KEYSTORE_EXTS) or any(h in name for h in NAME_HINTS)


def pem_fingerprints(data):
    for pem in PEM_RE.findall(data):
        try:
            der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii", "ignore"))
        except ValueError:
            continue
        yield hashlib.sha256(der).hexdigest().upper()


def keystore_fingerprints(data):
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(data)
        tmp.flush()
        for password in ("changeit", ""):
            result = subprocess.run(
                ["keytool", "-list", "-v", "-keystore", tmp.name, "-storepass", password],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                break
        else:
            return None
    return [
        m.replace(":", "").upper()
        for m in re.findall(r"SHA256:\s*([0-9A-F:]{95})", result.stdout, re.I)
    ]


def main():
    have_keytool = subprocess.run(["which", "keytool"], capture_output=True).returncode == 0
    findings, scanned_files, scanned_certs, skipped = [], 0, 0, []

    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as tar:
        for member in tar:
            if not member.isfile() or member.size > MAX_SIZE or not is_candidate(member.name):
                continue
            data = tar.extractfile(member).read()
            path = "/" + member.name.lstrip("./")

            if b"-----BEGIN CERTIFICATE-----" in data:
                fps = list(pem_fingerprints(data))
            elif path.lower().endswith(CERT_EXTS):
                fps = [hashlib.sha256(data).hexdigest().upper()]
            elif have_keytool:
                fps = keystore_fingerprints(data)
                if fps is None:
                    skipped.append(path)
                    continue
            else:
                skipped.append(path)
                continue

            if not fps:
                continue
            scanned_files += 1
            scanned_certs += len(fps)
            for fp in fps:
                if fp in DISTRUSTED:
                    findings.append((path, DISTRUSTED[fp], fp))

    print(f"Scanned {scanned_certs} certificates in {scanned_files} trust store files")
    for path in skipped:
        print(f"::debug::Could not read possible keystore {path}")
    for path, name, fp in findings:
        print(f"Distrusted root '{name}' ({fp}) found in {path}")
    return FOUND if findings else 0


if __name__ == "__main__":
    sys.exit(main())
