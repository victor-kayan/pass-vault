[windows]
set shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

test:
    python -m pytest -q

test-cov:
    python -m pytest --cov=password_manager --cov-report=term-missing

lint:
    python -m ruff check src tests
    python -m mypy src
    python -m pylint --errors-only src/password_manager

run *args:
    python -m password_manager {{args}}

