"""The SDK's flows in Chromium with PRF-capable virtual authenticators, against the real backend, through the
browser-test harness (SPEC §9): what the Node tests' fakes can't show. Two devices share one account.

    BACKEND_BIN=… python sdk/test/browser/test_flows.py      # needs playwright, chromium and socat"""

import shutil
import sys
import tempfile
from pathlib import Path

SDK = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SDK / "testing"))

from e2ee_store_harness import harness, new_device  # noqa: E402


def static_dir() -> Path:
    """The stand-in app with the SDK in `sdk/`, as an app ships it. Contents only: the sources may be read-only."""
    directory = Path(tempfile.mkdtemp())
    app = [(path, path.name) for path in (Path(__file__).parent / "app").iterdir()]
    sdk = [(path, Path("sdk") / path.relative_to(SDK / "src")) for path in (SDK / "src").rglob("*") if path.is_file()]
    for source, target in app + sdk:
        (directory / target).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, directory / target)
    return directory


def open_app(device) -> None:
    """Loads the app; on a reload, everything it held in memory (the master key) is gone."""
    device.page.goto("/")
    device.page.wait_for_function("window.app !== undefined")


def call(device, method: str, *args):
    return device.page.evaluate(f"(args) => window.app.{method}(...args)", list(args))


def run(browser, backend, port: int) -> None:
    base = f"http://localhost:{port}"
    laptop = new_device(browser, base)
    phone = new_device(browser, base, prf_at_create=False)

    # The first device creates the vault from the admin's setup link.
    open_app(laptop)
    call(laptop, "signup", backend.setup_token("user", "create", "alice"))
    created = call(laptop, "createVault")
    assert created["kind"] == "created" and created["prfAtCreate"], created
    assert call(laptop, "save", "from the laptop") == ["from the laptop"]
    open_app(laptop)
    assert call(laptop, "unlock") == "unlocked"

    # The second device joins with a setup link and the recovery key, then gets a passkey whose PRF output only
    # comes at sign-in.
    open_app(phone)
    call(phone, "signup", backend.setup_token("setup-token", "create", "alice"))
    joined = call(phone, "join", created["recoveryKey"])
    assert joined == {"notes": ["from the laptop"], "prfAtCreate": False}, joined
    open_app(phone)
    assert call(phone, "unlock") == "unlocked"
    assert call(phone, "save", "from the phone") == ["from the laptop", "from the phone"]

    # The laptop is a save behind: its change goes on top of the phone's.
    assert call(laptop, "save", "again") == ["from the laptop", "from the phone", "again"]

    # Cleanup reads the server's clock from the Date header; everything here is younger than a day.
    report = call(laptop, "maintain")
    assert report["error"] is None, report
    assert report["deleted"]["count"] == 0 and report["too_recent"]["count"] > 0, report

    # A file blob through the backend's ranges: whole, in ranges, pinned by its salt, and aborted while it streams.
    file = call(laptop, "file")
    assert file == {"ranges": [True] * 5, "pinned": True, "aborted": "next track"}, file

    # What the server saw: no plaintext, and no PRF output.
    assert all(b"from the laptop" not in blob for blob in backend.blob_contents())
    assert all(b'"results"' not in body for body in laptop.sent + phone.sent)


if __name__ == "__main__":
    app = static_dir()
    try:
        sys.exit(harness(run, str(app)))
    finally:
        shutil.rmtree(app)
