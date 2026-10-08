import string

import pytest

from password_manager.generator import ALPHABET, GROUPS, generate_password


@pytest.mark.parametrize("length", [12, 16, 20, 32, 64, 128, 256])
def test_length_and_character_groups(length: int) -> None:
    password = generate_password(length)
    assert len(password) == length
    assert all(char in ALPHABET for char in password)
    assert all(any(char in group for char in password) for group in GROUPS)


@pytest.mark.parametrize("length", [-1, 0, 4, 11, 257, 1000])
def test_invalid_length(length: int) -> None:
    with pytest.raises(ValueError):
        generate_password(length)


def test_default_length() -> None:
    assert len(generate_password()) == 20


def test_passwords_are_not_repeated() -> None:
    assert len({generate_password() for _ in range(100)}) == 100


def test_alphabet_has_no_whitespace() -> None:
    assert not any(char in string.whitespace for char in ALPHABET)
