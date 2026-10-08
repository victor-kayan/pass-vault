"""Geração de senhas com aleatoriedade do sistema operacional."""

import secrets
import string

GROUPS = (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+")
ALPHABET = "".join(GROUPS)


def generate_password(length: int = 20) -> str:
    if not 12 <= length <= 256:
        raise ValueError("o tamanho deve estar entre 12 e 256")
    chars = [secrets.choice(group) for group in GROUPS]
    chars.extend(secrets.choice(ALPHABET) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
