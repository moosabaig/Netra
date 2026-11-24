"""Download the external SSL scanners Netra can drive into ./tools.

    python setup_tools.py

  * sslscan     - Windows build from https://github.com/rbsec/sslscan/releases
  * testssl.sh  - https://github.com/testssl/testssl.sh (needs bash: Git Bash, WSL or Linux)

Versions are pinned; bump them here deliberately.
"""

import io
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

SSLSCAN_VERSION = "2.2.4"
TESTSSL_VERSION = "v3.2.5"

ROOT = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(ROOT, "tools")


def fetch(url):
    print(f"  downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "netra-setup"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def install_sslscan():
    dest = os.path.join(TOOLS, "sslscan")
    if sys.platform != "win32":
        print("sslscan: not Windows - install it with your package manager (apt install sslscan / brew install sslscan).")
        return
    url = f"https://github.com/rbsec/sslscan/releases/download/{SSLSCAN_VERSION}/sslscan-{SSLSCAN_VERSION}.zip"
    data = fetch(url)
    shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for member in zf.namelist():  # flatten, refuse path traversal
            name = os.path.basename(member)
            if not name or ".." in member:
                continue
            with zf.open(member) as src, open(os.path.join(dest, name), "wb") as out:
                shutil.copyfileobj(src, out)
    print(f"sslscan {SSLSCAN_VERSION} -> {dest}")


def install_testssl():
    dest = os.path.join(TOOLS, "testssl.sh")
    shutil.rmtree(dest, ignore_errors=True)
    if shutil.which("git"):
        subprocess.run(["git", "clone", "--quiet", "--depth", "1", "--branch", TESTSSL_VERSION,
                        "https://github.com/testssl/testssl.sh.git", dest], check=True)
    else:
        data = fetch(f"https://codeload.github.com/testssl/testssl.sh/tar.gz/refs/tags/{TESTSSL_VERSION}")
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            top = tf.getmembers()[0].name.split("/")[0]
            tf.extractall(TOOLS, filter="data")
        os.rename(os.path.join(TOOLS, top), dest)
    print(f"testssl.sh {TESTSSL_VERSION} -> {dest}")


if __name__ == "__main__":
    os.makedirs(TOOLS, exist_ok=True)
    install_sslscan()
    install_testssl()
    print("Done.")
