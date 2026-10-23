"""Browser-test harness for apps on e2ee-store: the real backend behind socat (as the iroh shim reaches it) and
Chromium with virtual authenticators that support PRF.

An app's tests put this directory on PYTHONPATH, set BACKEND_BIN to the backend binary, and call
`harness(run, static_dir)` with the directory of the app's static files."""

import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass

from playwright.sync_api import sync_playwright


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(condition, what: str, seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise TimeoutError(f"{what} within {seconds}s")


def healthy(port: int) -> bool:
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{port}/healthz", headers={"Host": f"localhost:{port}"})
        with urllib.request.urlopen(request, timeout=1) as response:
            return response.status == 200
    except OSError:
        return False


class Backend:
    def __init__(self, work: str, static_dir: str):
        self.binary = os.environ["BACKEND_BIN"]
        self.env = {
            **os.environ,
            "BACKEND_SOCKET": os.path.join(work, "backend.sock"),
            "BACKEND_DATABASE": os.path.join(work, "backend.sqlite3"),
            "BACKEND_STATIC_DIR": static_dir,
        }
        self.database = self.env["BACKEND_DATABASE"]
        self.config = ["--config", os.path.join(work, "none.toml")]

    def cli(self, *args: str) -> str:
        return subprocess.run([self.binary, *self.config, *args], env=self.env, check=True, capture_output=True, text=True).stdout

    def setup_token(self, *args: str) -> str:
        return re.search(r"#setup=(\S+)", self.cli(*args)).group(1)

    def blob_contents(self) -> list[bytes]:
        with sqlite3.connect(self.database) as db:
            return [row[0] for row in db.execute("SELECT content FROM blobs")]


# Like the Android app's WebAuthn: PRF is enabled at registration, but its output only comes at sign-in.
NO_PRF_AT_CREATE = """
(() => {
  const create = navigator.credentials.create.bind(navigator.credentials);
  navigator.credentials.create = async (options) => {
    const credential = await create(options);
    const results = credential.getClientExtensionResults.bind(credential);
    credential.getClientExtensionResults = () => ({ ...results(), prf: { enabled: true } });
    if (credential.toJSON) {
      const toJSON = credential.toJSON.bind(credential);
      credential.toJSON = () => ({ ...toJSON(), clientExtensionResults: { prf: { enabled: true } } });
    }
    return credential;
  };
})();
"""


AUTHENTICATOR = {
    "protocol": "ctap2",
    "ctap2Version": "ctap2_1",
    "transport": "internal",
    "hasResidentKey": True,
    "hasUserVerification": True,
    "isUserVerified": True,
    "hasPrf": True,
}


@dataclass
class Device:
    """A browser profile with its own platform authenticator that supports PRF."""

    page: object
    sent: list
    cdp: object
    authenticator: str
    committed: list  # root directory blob IDs this device committed (successful writes of the `vault` ref)

    def replace_authenticator(self) -> None:
        """Swaps in a new, empty authenticator: like losing the old security key and using a new one."""
        self.cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": self.authenticator})
        self.authenticator = self.cdp.send("WebAuthn.addVirtualAuthenticator", {"options": AUTHENTICATOR})["authenticatorId"]


def new_device(browser, base: str, prf_at_create: bool = True) -> Device:
    context = browser.new_context(base_url=base)
    if not prf_at_create:
        context.add_init_script(NO_PRF_AT_CREATE)
    context.grant_permissions(["clipboard-read", "clipboard-write"], origin=base)
    page = context.new_page()
    page.on("dialog", lambda dialog: dialog.accept())
    cdp = context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": AUTHENTICATOR})["authenticatorId"]
    sent: list[bytes] = []
    page.on("request", lambda request: sent.append(request.post_data_buffer or b"") if "/api/v1/" in request.url else None)
    committed: list[str] = []

    def record_commit(response) -> None:
        if response.request.method == "PUT" and response.url.endswith("/api/v1/refs/vault") and response.status in (200, 201):
            committed.append(json.loads(response.request.post_data)["blob"])

    page.on("response", record_commit)
    return Device(page, sent, cdp, authenticator, committed)


def harness(run, static_dir: str, extra_env: dict | None = None) -> int:
    """Starts the backend serving `static_dir` and the shim, runs `run(browser, backend, port)`, and stops everything."""
    work = tempfile.mkdtemp()
    backend = Backend(work, static_dir)
    backend.env.update(extra_env or {})
    socket_path = backend.env["BACKEND_SOCKET"]
    port = free_port()
    log_path = os.path.join(work, "server.log")
    processes = []  # stopped in reverse order, whatever happens
    failed = False
    try:
        with open(log_path, "w") as log:
            backend.cli("user", "list")  # creates and migrates the database
            server = subprocess.Popen([backend.binary, *backend.config, "serve"], env=backend.env, stdout=log, stderr=log)
        processes.append(server)
        wait_for(lambda: os.path.exists(socket_path) or server.poll() is not None, "the socket to appear")
        if server.poll() is not None:
            raise RuntimeError(f"the backend exited with {server.returncode}")
        processes.append(subprocess.Popen(["socat", f"TCP-LISTEN:{port},bind=127.0.0.1,fork,reuseaddr", f"UNIX-CONNECT:{socket_path}"], stderr=subprocess.DEVNULL))
        wait_for(lambda: healthy(port), "the backend answering through socat")
        with sync_playwright() as playwright:
            # No sandbox: Chromium's needs user namespaces, which the Nix build sandbox doesn't offer.
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"), args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                run(browser, backend, port)
            finally:
                browser.close()
    except BaseException:
        failed = True
        raise
    finally:
        for process in reversed(processes):
            process.terminate()
            process.wait(timeout=10)
        if failed:
            print("--- backend log ---\n" + open(log_path).read(), flush=True)
        socket_left = os.path.exists(socket_path)
        shutil.rmtree(work, ignore_errors=True)
    assert not socket_left, "the socket is removed on shutdown"
    print("passed")
    return 0
