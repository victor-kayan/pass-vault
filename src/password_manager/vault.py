"""Formato do vault, operações de entradas e E/S protegida por bloqueio."""

import base64
import binascii
import importlib
import json
import os
import secrets
import stat
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from .crypto import AuthenticationError, KdfParams, decrypt, derive_key, encrypt

MAX_FILE_SIZE = 16 * 1024 * 1024


class VaultError(Exception):
    """Erro esperado ao operar o vault."""


class VaultFormatError(VaultError):
    """Arquivo ausente, inválido ou com permissões inseguras."""


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def validate_name(name: str) -> None:
    if not name or len(name) > 128 or any(c.isspace() or not c.isprintable() for c in name):
        raise ValueError("o nome deve ter 1 a 128 caracteres, sem espaços ou controles")


@dataclass
class Entry:
    username: str
    password: str
    url: str
    notes: str
    created_at: str
    updated_at: str
    last_used_at: str = ""

    @classmethod
    def from_dict(cls, value: object) -> "Entry":
        if not isinstance(value, dict):
            raise VaultFormatError("entrada inválida")
        fields = ("username", "password", "url", "notes", "created_at", "updated_at")
        if any(not isinstance(value.get(field), str) for field in fields):
            raise VaultFormatError("campos da entrada inválidos")
        last_used = value.get("last_used_at", "")
        if not isinstance(last_used, str):
            raise VaultFormatError("último uso inválido")
        return cls(
            value["username"], value["password"], value["url"], value["notes"],
            value["created_at"], value["updated_at"], last_used_at=last_used,
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object, size: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise VaultFormatError("base64 inválido")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VaultFormatError("base64 inválido") from exc
    if size is not None and len(data) != size:
        raise VaultFormatError("tamanho de campo inválido")
    return data


def _metadata(salt: bytes, params: KdfParams, nonce: bytes) -> dict[str, Any]:
    return {
        "version": 1,
        "kdf": {
            "name": "argon2id",
            "salt": _b64(salt),
            "time_cost": params.time_cost,
            "memory_cost": params.memory_cost,
            "parallelism": params.parallelism,
        },
        "cipher": {"name": "aes-256-gcm", "nonce": _b64(nonce)},
    }


def _check_private(fd: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise VaultFormatError("o caminho não é um arquivo regular")
    # getattr mantém esta verificação tipável também no Windows, onde getuid não existe.
    if os.name == "posix" and (info.st_uid != getattr(os, "getuid")() or info.st_mode & 0o077):  # noqa: B009
        raise VaultFormatError("arquivo deve pertencer ao usuário e ter modo 0600")


def _open_file(path: Path, flags: int, mode: int = 0o600) -> int:
    if path.is_symlink():
        raise VaultFormatError("links simbólicos não são aceitos")
    fd = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        _check_private(fd)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_file(path: Path) -> bytes:
    try:
        fd = _open_file(path, os.O_RDONLY)
    except FileNotFoundError as exc:
        raise VaultError("vault não encontrado; execute 'pv init'") from exc
    with os.fdopen(fd, "rb") as file:
        if os.fstat(file.fileno()).st_size > MAX_FILE_SIZE:
            raise VaultFormatError("vault excede o limite de 16 MiB")
        data = file.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        raise VaultFormatError("vault excede o limite de 16 MiB")
    return data


def _atomic_write(path: Path, data: bytes) -> None:
    if len(data) > MAX_FILE_SIZE:
        raise VaultError("vault excede o limite de 16 MiB")
    fd, temporary = tempfile.mkstemp(prefix=".pv-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        # Em POSIX, sincronizar o diretório torna o rename durável.
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY"))  # noqa: B009
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Vault:
    """Uma sessão exclusiva. Use sempre dentro de ``with Vault(path)``."""

    def __init__(self, path: Path):
        self.path = path.expanduser()
        self.entries: dict[str, Entry] = {}
        self._lock_fd: int | None = None
        self._key: bytes | None = None
        self._salt: bytes | None = None
        self._params: KdfParams | None = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            parent = self.path.parent.stat()
            if parent.st_uid != getattr(os, "getuid")() or parent.st_mode & 0o077:  # noqa: B009
                raise VaultFormatError("diretório do vault deve ter modo 0700")
        lock_path = self.path.with_name(self.path.name + ".lock")
        fd = _open_file(lock_path, os.O_RDWR | os.O_CREAT)
        try:
            if os.name == "nt":
                import msvcrt  # importação apenas no Windows

                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                    os.fsync(fd)
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            else:
                fcntl = importlib.import_module("fcntl")
                fcntl.flock(fd, fcntl.LOCK_EX)
        except BaseException:
            os.close(fd)
            raise
        self._lock_fd = fd
        return self

    def __exit__(self, *_: object) -> None:
        self.entries.clear()
        self._key = None  # limpeza de referências; Python não garante apagar bytes da RAM
        self._salt = None
        self._params = None
        if self._lock_fd is not None:
            if os.name == "nt":
                import msvcrt

                os.lseek(self._lock_fd, 0, os.SEEK_SET)
                msvcrt.locking(self._lock_fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl = importlib.import_module("fcntl")
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None

    def initialize(self, password: str, params: KdfParams | None = None) -> None:
        self._require_lock()
        if self.path.exists() or self.path.is_symlink():
            raise VaultError("vault já existe")
        if len(password) < 8:
            raise ValueError("senha mestra deve ter pelo menos 8 caracteres")
        params = params or KdfParams()
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt, params)
        self._salt, self._params, self._key = salt, params, key
        self.entries = {}
        self.save()

    def unlock(self, password: str) -> None:
        self._require_lock()
        try:
            envelope = json.loads(_read_file(self.path))
            if not isinstance(envelope, dict) or envelope.get("version") != 1:
                raise VaultFormatError("versão de vault inválida")
            kdf, cipher = envelope["kdf"], envelope["cipher"]
            if not isinstance(kdf, dict) or not isinstance(cipher, dict):
                raise VaultFormatError("envelope inválido")
            if kdf.get("name") != "argon2id" or cipher.get("name") != "aes-256-gcm":
                raise VaultFormatError("algoritmo não suportado")
            raw_params = [kdf[field] for field in ("time_cost", "memory_cost", "parallelism")]
            if any(type(value) is not int for value in raw_params):
                raise VaultFormatError("parâmetros Argon2id inválidos")
            params = KdfParams(*raw_params)
            params.validate()
            salt = _unb64(kdf["salt"], 16)
            nonce = _unb64(cipher["nonce"], 12)
            ciphertext = _unb64(cipher["ciphertext"])
            if len(ciphertext) < 16:
                raise VaultFormatError("ciphertext inválido")
            key = derive_key(password, salt, params)
            plaintext = decrypt(ciphertext, key, nonce, _json_bytes(_metadata(salt, params, nonce)))
            raw_entries = json.loads(plaintext)
            if not isinstance(raw_entries, dict):
                raise VaultFormatError("entradas inválidas")
            entries: dict[str, Entry] = {}
            for name, value in raw_entries.items():
                validate_name(name)
                entries[name] = Entry.from_dict(value)
        except AuthenticationError as exc:
            raise VaultError("senha incorreta ou vault corrompido") from exc
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultFormatError("formato de vault inválido") from exc
        self._salt, self._params, self._key, self.entries = salt, params, key, entries

    def save(self) -> None:
        self._require_lock()
        if self._salt is None or self._params is None or self._key is None:
            raise VaultError("vault bloqueado")
        nonce = secrets.token_bytes(12)
        metadata = _metadata(self._salt, self._params, nonce)
        plaintext = _json_bytes({name: entry.to_dict() for name, entry in self.entries.items()})
        ciphertext = encrypt(plaintext, self._key, nonce, _json_bytes(metadata))
        metadata["cipher"]["ciphertext"] = _b64(ciphertext)
        _atomic_write(self.path, _json_bytes(metadata) + b"\n")

    def change_password(self, password: str) -> None:
        self._require_unlocked()
        if len(password) < 8:
            raise ValueError("senha mestra deve ter pelo menos 8 caracteres")
        params = KdfParams()
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt, params)
        self._salt, self._params, self._key = salt, params, key
        self.save()

    def add(self, name: str, entry: Entry, overwrite: bool = False) -> None:
        self._require_unlocked()
        validate_name(name)
        if name in self.entries and not overwrite:
            raise VaultError("entrada já existe; use --force para substituí-la")
        if name in self.entries:
            entry.created_at = self.entries[name].created_at
        self.entries[name] = entry
        self.save()

    def get(self, name: str, touch: bool = False) -> Entry:
        self._require_unlocked()
        try:
            entry = self.entries[name]
        except KeyError as exc:
            raise VaultError("entrada não encontrada") from exc
        if touch:
            entry.last_used_at = now()
            self.save()
        return entry

    def delete(self, name: str) -> None:
        self._require_unlocked()
        if name not in self.entries:
            raise VaultError("entrada não encontrada")
        del self.entries[name]
        self.save()

    def names(self) -> list[str]:
        self._require_unlocked()
        return sorted(self.entries, key=str.casefold)

    def _require_lock(self) -> None:
        if self._lock_fd is None:
            raise RuntimeError("use o vault dentro de um bloco 'with'")

    def _require_unlocked(self) -> None:
        self._require_lock()
        if self._key is None:
            raise VaultError("vault bloqueado")
