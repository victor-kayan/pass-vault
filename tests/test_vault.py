import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from password_manager.crypto import KdfParams
from password_manager.vault import Entry, Vault, VaultError, VaultFormatError, now

MASTER = "senha-mestra-forte"


def entry(password: str = "segredo") -> Entry:
    timestamp = now()
    return Entry("alice", password, "https://example.com", "nota", timestamp, timestamp)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)


def test_create_and_unlock(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        assert vault.names() == []


def test_file_contains_no_plaintext(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        vault.add("github", entry("senha-unica-muito-secreta"))
    data = vault_path.read_bytes()
    assert b"senha-unica-muito-secreta" not in data
    assert b"github" not in data
    assert read_json(vault_path)["kdf"]["name"] == "argon2id"


def test_wrong_master_password(vault_path: Path) -> None:
    with Vault(vault_path) as vault, pytest.raises(VaultError, match="senha incorreta"):
        vault.unlock("senha-errada")


def test_init_does_not_overwrite_existing_vault(vault_path: Path, params: KdfParams) -> None:
    before = vault_path.read_bytes()
    with Vault(vault_path) as vault, pytest.raises(VaultError, match="já existe"):
        vault.initialize("outra-senha", params)
    assert vault_path.read_bytes() == before


@pytest.mark.parametrize("password", ["", "1234567"])
def test_rejects_short_master(tmp_path: Path, params: KdfParams, password: str) -> None:
    path = tmp_path / "vault.json"
    with Vault(path) as vault, pytest.raises(ValueError):
        vault.initialize(password, params)
    assert not path.exists()


def test_add_and_get(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        vault.add("github", entry())
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        assert vault.get("github").password == "segredo"


def test_duplicate_does_not_change_file(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        vault.add("github", entry())
        before = vault_path.read_bytes()
        with pytest.raises(VaultError, match="já existe"):
            vault.add("github", entry("nova"))
    assert vault_path.read_bytes() == before


def test_force_preserves_creation_time(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        first = entry()
        first.created_at = "2020-01-01T00:00:00+00:00"
        vault.add("github", first)
        vault.add("github", entry("nova"), overwrite=True)
        assert vault.get("github").created_at == "2020-01-01T00:00:00+00:00"
        assert vault.get("github").password == "nova"


@pytest.mark.parametrize("name", ["", "dois nomes", "com\nlinha", "x" * 129])
def test_rejects_invalid_entry_name(vault_path: Path, name: str) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        with pytest.raises(ValueError):
            vault.add(name, entry())


def test_missing_entry(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        with pytest.raises(VaultError, match="não encontrada"):
            vault.get("inexistente")


def test_delete(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        vault.add("github", entry())
        vault.delete("github")
        assert vault.names() == []
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        assert vault.names() == []


def test_delete_missing(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        with pytest.raises(VaultError):
            vault.delete("inexistente")


def test_names_sorted_case_insensitively(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        for name in ("zulu", "Beta", "alpha"):
            vault.add(name, entry())
        assert vault.names() == ["alpha", "Beta", "zulu"]


def test_get_updates_last_used_only_when_requested(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        vault.add("github", entry())
        assert vault.get("github").last_used_at == ""
        assert vault.get("github", touch=True).last_used_at
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        assert vault.get("github").last_used_at


def test_legacy_entry_without_last_used() -> None:
    old = entry().to_dict()
    del old["last_used_at"]
    assert Entry.from_dict(old).last_used_at == ""


def test_change_password_reencrypts_and_preserves_entries(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        vault.add("github", entry())
        old_salt = read_json(vault_path)["kdf"]["salt"]
        vault.change_password("uma-nova-senha-mestra")
    assert read_json(vault_path)["kdf"]["salt"] != old_salt
    with Vault(vault_path) as vault:
        with pytest.raises(VaultError):
            vault.unlock(MASTER)
        vault.unlock("uma-nova-senha-mestra")
        assert vault.get("github").password == "segredo"


def test_short_new_master_does_not_change_file(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        before = vault_path.read_bytes()
        with pytest.raises(ValueError):
            vault.change_password("curta")
    assert vault_path.read_bytes() == before


def test_save_changes_nonce(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        first = read_json(vault_path)["cipher"]["nonce"]
        vault.save()
        assert read_json(vault_path)["cipher"]["nonce"] != first


@pytest.mark.parametrize("field", ["ciphertext", "nonce"])
def test_tamper_cipher_is_rejected(vault_path: Path, field: str) -> None:
    data = read_json(vault_path)
    raw = bytearray(base64.b64decode(data["cipher"][field]))
    raw[0] ^= 1
    data["cipher"][field] = base64.b64encode(raw).decode()
    write_json(vault_path, data)
    with Vault(vault_path) as vault, pytest.raises(VaultError):
        vault.unlock(MASTER)


def test_tamper_kdf_metadata_is_rejected(vault_path: Path) -> None:
    data = read_json(vault_path)
    data["kdf"]["time_cost"] = 2
    write_json(vault_path, data)
    with Vault(vault_path) as vault, pytest.raises(VaultError):
        vault.unlock(MASTER)


@pytest.mark.parametrize(
    "change",
    [
        lambda data: data.update(version=2),
        lambda data: data["kdf"].update(name="pbkdf2"),
        lambda data: data["kdf"].update(memory_cost=1_000_000),
        lambda data: data["kdf"].update(time_cost=True),
        lambda data: data["cipher"].update(nonce="not base64!!!"),
    ],
)
def test_invalid_envelope(vault_path: Path, change) -> None:
    data = read_json(vault_path)
    change(data)
    write_json(vault_path, data)
    with Vault(vault_path) as vault, pytest.raises(VaultError):
        vault.unlock(MASTER)


def test_invalid_json(vault_path: Path) -> None:
    vault_path.write_text("{", encoding="utf-8")
    with Vault(vault_path) as vault, pytest.raises(VaultFormatError):
        vault.unlock(MASTER)


def test_no_orphan_temporary_file(vault_path: Path) -> None:
    with Vault(vault_path) as vault:
        vault.unlock(MASTER)
        vault.add("github", entry())
    assert list(vault_path.parent.glob(".pv-*")) == []


def test_second_process_waits_for_lock(vault_path: Path) -> None:
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "from password_manager.vault import Vault\n"
        "with Vault(Path(sys.argv[1])):\n"
        "    print('entered', flush=True)\n"
    )
    with Vault(vault_path):
        process = subprocess.Popen(
            [sys.executable, "-c", code, str(vault_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            with pytest.raises(subprocess.TimeoutExpired):
                process.communicate(timeout=0.5)
        except BaseException:
            process.kill()
            process.communicate()
            raise
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == 0, stderr
    assert stdout.strip() == "entered"


@pytest.mark.skipif(os.name != "posix", reason="permissões POSIX")
def test_vault_file_mode(vault_path: Path) -> None:
    assert vault_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="permissões POSIX")
def test_weak_file_permissions_rejected(vault_path: Path) -> None:
    vault_path.chmod(0o644)
    with Vault(vault_path) as vault, pytest.raises(VaultFormatError):
        vault.unlock(MASTER)
