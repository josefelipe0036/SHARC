"""Host-key checking for the SSH connections of the GUI.

A host seen for the first time is trusted and added to the user's known_hosts, as
``ssh -o StrictHostKeyChecking=accept-new`` does. A host whose key differs from the stored one
never reaches the policy: paramiko refuses it (BadHostKeyException), so a man in the middle cannot
take the password or the session. Qt-free, so it can be unit tested.
"""
import os
from typing import Callable, Optional

import paramiko


def default_known_hosts() -> str:
    """The known_hosts of the user, shared with the system ssh (the tunnel uses it too)."""
    return os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")


def _ends_with_newline(path: str) -> bool:
    with open(path, "rb") as fh:
        fh.seek(-1, os.SEEK_END)
        return fh.read(1) == b"\n"


class TrustOnFirstUsePolicy(paramiko.MissingHostKeyPolicy):
    """Accept an unknown host once and store its key; a changed key is refused before this policy."""

    def __init__(self, known_hosts: str, log: Optional[Callable[[str], None]] = None):
        self.known_hosts = known_hosts
        self.log = log

    def missing_host_key(self, client, hostname, key):
        """Append the new host key to known_hosts and accept the connection."""
        folder = os.path.dirname(self.known_hosts)
        if folder:
            os.makedirs(folder, mode=0o700, exist_ok=True)
        line = paramiko.hostkeys.HostKeyEntry([hostname], key).to_line()
        if os.path.isfile(self.known_hosts) and os.path.getsize(self.known_hosts) > 0 \
                and not _ends_with_newline(self.known_hosts):
            line = "\n" + line
        with open(self.known_hosts, "a", encoding="utf-8") as fh:
            fh.write(line)
        client.get_host_keys().add(hostname, key.get_name(), key)
        if self.log:
            fingerprint = getattr(key, "fingerprint", None) or key.get_fingerprint().hex()
            self.log(f"[SSH] New host {hostname}: {key.get_name()} key {fingerprint} added to {self.known_hosts}")


def apply_host_key_policy(client: paramiko.SSHClient, known_hosts: Optional[str] = None,
                          log: Optional[Callable[[str], None]] = None) -> None:
    """Load the known host keys into `client` and make it trust a new host on first use only."""
    path = known_hosts or default_known_hosts()
    if os.path.isfile(path):
        client.load_system_host_keys(path)
    client.set_missing_host_key_policy(TrustOnFirstUsePolicy(path, log))


def changed_key_hint(known_hosts: Optional[str] = None) -> str:
    """What to tell the user when a server presents a key different from the stored one."""
    return ("[SSH] The server key changed since the last connection: the connection was refused, as it could be a "
            "man-in-the-middle. If the server was reinstalled, remove its line from "
            f"{known_hosts or default_known_hosts()} and connect again.")
