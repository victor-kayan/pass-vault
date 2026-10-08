"""Primitivas criptográficas. Esta camada recebe e devolve apenas bytes."""

from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AuthenticationError(Exception):
    """Senha incorreta ou dados autenticados alterados."""


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 3
    memory_cost: int = 65_536  # KiB: 64 MiB
    parallelism: int = 4

    def validate(self) -> None:
        # O arquivo é controlável por terceiros. Limites evitam consumo excessivo.
        if not 1 <= self.time_cost <= 10:
            raise ValueError("time_cost inválido")
        if not 8_192 <= self.memory_cost <= 262_144:
            raise ValueError("memory_cost inválido")
        if not 1 <= self.parallelism <= 8:
            raise ValueError("parallelism inválido")
        if self.memory_cost < 8 * self.parallelism:
            raise ValueError("memory_cost insuficiente")


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    """Deriva uma chave AES de 256 bits com Argon2id."""
    params.validate()
    if len(salt) != 16:
        raise ValueError("salt deve ter 16 bytes")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=32,
        type=Type.ID,
    )


def encrypt(plaintext: bytes, key: bytes, nonce: bytes, associated_data: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("chave ou nonce inválido")
    return AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, associated_data: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("chave ou nonce inválido")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise AuthenticationError("senha incorreta ou vault corrompido") from exc
