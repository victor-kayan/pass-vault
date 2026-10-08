from pathlib import Path

import pytest

from password_manager.main import main
from password_manager.vault import Entry, Vault, now


def run(path: Path, *args: str) -> int:
    return main(["--vault", str(path), *args])


def test_init_prompts_twice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "vault.json"
    answers = iter(["senha-mestra-forte", "senha-mestra-forte"])
    monkeypatch.setattr("getpass.getpass", lambda _: next(answers))
    assert run(path, "init") == 0
    assert path.exists()


def test_init_rejects_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "vault.json"
    answers = iter(["senha-mestra-forte", "outra-senha-forte"])
    monkeypatch.setattr("getpass.getpass", lambda _: next(answers))
    assert run(path, "init") == 1
    assert not path.exists()


def test_count_prints_only_number(
    vault_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda _: "senha-mestra-forte")
    assert run(vault_path, "count") == 0
    assert capsys.readouterr().out == "0\n"


def test_add_get_list_search_delete(
    vault_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda _: "senha-mestra-forte")
    answers = iter(["alice", "https://example.com", "nota"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert run(vault_path, "add", "GitHub", "--generate") == 0
    capsys.readouterr()

    assert run(vault_path, "count") == 0
    assert capsys.readouterr().out == "1\n"
    assert run(vault_path, "list") == 0
    assert "GitHub\talice\t" in capsys.readouterr().out
    assert run(vault_path, "search", "hub") == 0
    assert capsys.readouterr().out == "GitHub\n"
    assert run(vault_path, "get", "GitHub") == 0
    assert "Senha: ********" in capsys.readouterr().out
    assert run(vault_path, "get", "GitHub", "--show") == 0
    output = capsys.readouterr().out
    assert "Senha: ********" not in output
    assert "Senha: " in output
    assert run(vault_path, "delete", "GitHub") == 0
    capsys.readouterr()
    assert run(vault_path, "count") == 0
    assert capsys.readouterr().out == "0\n"


def test_get_updates_last_used(vault_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with Vault(vault_path) as vault:
        vault.unlock("senha-mestra-forte")
        timestamp = now()
        vault.add("site", Entry("alice", "segredo", "", "", timestamp, timestamp))
    monkeypatch.setattr("getpass.getpass", lambda _: "senha-mestra-forte")
    assert run(vault_path, "get", "site") == 0
    with Vault(vault_path) as vault:
        vault.unlock("senha-mestra-forte")
        assert vault.get("site").last_used_at


def test_get_escapes_terminal_controls(
    vault_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with Vault(vault_path) as vault:
        vault.unlock("senha-mestra-forte")
        timestamp = now()
        vault.add("site", Entry("alice\x1b[31m", "segredo\nnovo", "", "", timestamp, timestamp))
    monkeypatch.setattr("getpass.getpass", lambda _: "senha-mestra-forte")
    assert run(vault_path, "get", "site", "--show") == 0
    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "Usuário: alice\\x1b[31m" in output
    assert "Senha: segredo\\nnovo" in output


def test_search_rejects_empty_query(vault_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("getpass.getpass", lambda _: "senha-mestra-forte")
    assert run(vault_path, "search", "") == 1


@pytest.mark.parametrize("length", [12, 20, 64])
def test_gen_works_without_vault(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], length: int
) -> None:
    assert run(tmp_path / "absent.json", "gen", str(length)) == 0
    assert len(capsys.readouterr().out.strip()) == length


def test_just_separator_is_accepted(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--", "gen", "12"]) == 0
    assert len(capsys.readouterr().out.strip()) == 12


def test_wrong_password_prints_safe_error(
    vault_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda _: "errada")
    assert run(vault_path, "list") == 1
    assert "senha incorreta ou vault corrompido" in capsys.readouterr().err
