from pathlib import Path

import pytest

from password_manager.crypto import KdfParams
from password_manager.vault import Vault


@pytest.fixture
def params() -> KdfParams:
    # Custo reduzido somente nos testes; a CLI usa os padrões de produção.
    return KdfParams(time_cost=1, memory_cost=8192, parallelism=1)


@pytest.fixture
def vault_path(tmp_path: Path, params: KdfParams) -> Path:
    path = tmp_path / "vault.json"
    with Vault(path) as vault:
        vault.initialize("senha-mestra-forte", params)
    return path
