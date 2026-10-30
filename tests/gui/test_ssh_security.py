"""Comandos remotos e verificação da chave do servidor SSH."""
import shlex
import shutil
import socket
import subprocess
import threading

import pytest

paramiko = pytest.importorskip("paramiko")
pytest.importorskip("PySide6")

from core.ssh_host_keys import apply_host_key_policy  # noqa: E402
from managers.ssh_runner import RunnerManager  # noqa: E402

HOSTILE = ["/home/a b/SHARC/.venv/bin/activate", "x'; touch PWNED; echo '", "$(touch PWNED)", "a\"b`touch PWNED`"]


@pytest.fixture
def runner():
    """Um RunnerManager sem conexão, que só monta comandos."""
    return RunnerManager(log_callback=lambda msg: None, update_row_callback=None)


@pytest.mark.parametrize("value", HOSTILE)
def test_remote_quote_round_trips_through_the_shell_parser(runner, value):
    """O valor citado volta inteiro e sozinho quando o shell separa as palavras."""
    assert shlex.split(runner._quote_remote_single(value)) == [value]


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("value", HOSTILE)
def test_activation_prefix_never_runs_text_of_the_venv_path(runner, value, tmp_path):
    """Um caminho de venv com aspas ou $(...) é só texto: nada dele é executado."""
    runner.remote_venv_path = value
    done = subprocess.run(["bash", "-c", runner._build_remote_activation_prefix()], cwd=tmp_path,
                          capture_output=True, text=True, timeout=10)
    assert done.returncode == 0, done.stderr
    assert value in done.stdout
    assert not (tmp_path / "PWNED").exists()


def test_module_entrypoint_is_quoted(runner):
    """O main_cli como módulo também é citado."""
    runner.remote_main_cli_rel = "sharc.main_cli; touch PWNED"
    cmd = runner._build_remote_python_entrypoint("/tmp/a b.yaml")
    assert shlex.split(cmd) == ["python3", "-m", "sharc.main_cli; touch PWNED", "-p", "/tmp/a b.yaml"]


class _AcceptAll(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL


@pytest.fixture
def ssh_server():
    """Servidor SSH local de uma conexão, com a chave de host dada; devolve a porta."""
    opened = []

    def start(host_key):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        opened.append(listener)

        def serve():
            conn, _ = listener.accept()
            transport = paramiko.Transport(conn)
            opened.append(transport)
            transport.add_server_key(host_key)
            try:
                transport.start_server(server=_AcceptAll())
            except (paramiko.SSHException, EOFError, OSError):
                pass

        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname()[1]

    yield start
    for item in opened:
        item.close()


def _connect(port, known_hosts):
    client = paramiko.SSHClient()
    apply_host_key_policy(client, known_hosts=str(known_hosts))
    try:
        client.connect("127.0.0.1", port=port, username="u", password="p", timeout=10,
                       allow_agent=False, look_for_keys=False)
    finally:
        client.close()


def test_first_connection_stores_the_host_key(ssh_server, tmp_path):
    """Um servidor novo é aceito e a chave vai para o known_hosts, sem estragar o que já estava lá."""
    key = paramiko.RSAKey.generate(2048)
    port = ssh_server(key)
    known_hosts = tmp_path / ".ssh" / "known_hosts"
    known_hosts.parent.mkdir()
    known_hosts.write_text("# hosts of the user, no newline at the end")

    _connect(port, known_hosts)

    assert known_hosts.read_text().startswith("# hosts of the user, no newline at the end\n")
    stored = paramiko.HostKeys(str(known_hosts)).lookup(f"[127.0.0.1]:{port}")
    assert stored is not None and stored["ssh-rsa"] == key


def test_changed_host_key_is_refused(ssh_server, tmp_path):
    """Se a chave do servidor mudou, a conexão é recusada antes da senha e o known_hosts não muda."""
    trusted, attacker = paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)
    port = ssh_server(attacker)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(paramiko.hostkeys.HostKeyEntry([f"[127.0.0.1]:{port}"], trusted).to_line())
    before = known_hosts.read_text()

    with pytest.raises(paramiko.BadHostKeyException):
        _connect(port, known_hosts)

    assert known_hosts.read_text() == before
