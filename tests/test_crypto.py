import secrets

import pytest

from password_manager.crypto import AuthenticationError, KdfParams, decrypt, derive_key, encrypt


def test_derive_key_is_deterministic(params: KdfParams) -> None:
    salt = secrets.token_bytes(16)
    assert derive_key("senha", salt, params) == derive_key("senha", salt, params)


def test_derive_key_has_256_bits(params: KdfParams) -> None:
    assert len(derive_key("senha", secrets.token_bytes(16), params)) == 32


def test_different_salts_change_key(params: KdfParams) -> None:
    assert derive_key("senha", b"a" * 16, params) != derive_key("senha", b"b" * 16, params)


def test_different_passwords_change_key(params: KdfParams) -> None:
    assert derive_key("senha1", b"a" * 16, params) != derive_key("senha2", b"a" * 16, params)


def test_unicode_password(params: KdfParams) -> None:
    assert derive_key("café 🔐", b"a" * 16, params) != derive_key("cafe 🔐", b"a" * 16, params)


@pytest.mark.parametrize("salt", [b"", b"a" * 15, b"a" * 17])
def test_rejects_invalid_salt(params: KdfParams, salt: bytes) -> None:
    with pytest.raises(ValueError):
        derive_key("senha", salt, params)


@pytest.mark.parametrize(
    "params",
    [
        KdfParams(0, 8192, 1),
        KdfParams(11, 8192, 1),
        KdfParams(1, 8191, 1),
        KdfParams(1, 262145, 1),
        KdfParams(1, 8192, 0),
        KdfParams(1, 8192, 9),
    ],
)
def test_rejects_unsafe_kdf_params(params: KdfParams) -> None:
    with pytest.raises(ValueError):
        params.validate()


def test_encrypt_decrypt_round_trip() -> None:
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    assert decrypt(encrypt(b"segredo", key, nonce, b"meta"), key, nonce, b"meta") == b"segredo"


@pytest.mark.parametrize("field", ["key", "nonce", "aad", "ciphertext"])
def test_authenticated_data_rejects_changes(field: str) -> None:
    key, nonce, aad = secrets.token_bytes(32), secrets.token_bytes(12), b"meta"
    ciphertext = encrypt(b"segredo", key, nonce, aad)
    if field == "key":
        key = secrets.token_bytes(32)
    elif field == "nonce":
        nonce = secrets.token_bytes(12)
    elif field == "aad":
        aad = b"alterado"
    else:
        ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    with pytest.raises(AuthenticationError):
        decrypt(ciphertext, key, nonce, aad)


@pytest.mark.parametrize("key,nonce", [(b"a" * 31, b"b" * 12), (b"a" * 32, b"b" * 11)])
def test_rejects_invalid_cipher_inputs(key: bytes, nonce: bytes) -> None:
    with pytest.raises(ValueError):
        encrypt(b"x", key, nonce, b"")
