"""Interface de linha de comando do Pass Vault."""

import argparse
import getpass
import os
import sys
from pathlib import Path

from .generator import generate_password
from .vault import Entry, Vault, VaultError, now


def _master(prompt: str = "Senha mestra: ") -> str:
    return getpass.getpass(prompt)


def _new_master() -> str:
    password = _master("Nova senha mestra: ")
    if len(password) < 8:
        raise ValueError("senha mestra deve ter pelo menos 8 caracteres")
    if password != _master("Confirme a senha mestra: "):
        raise ValueError("as senhas mestras não coincidem")
    return password


def _display(value: str) -> str:
    """Escapa controles para uma entrada não executar comandos no terminal."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pv", description="Gerenciador local de senhas")
    parser.add_argument("--vault", type=Path, default=None, help="caminho do arquivo criptografado")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="cria um vault vazio")
    add = commands.add_parser("add", help="adiciona uma credencial")
    add.add_argument("name")
    add.add_argument("--generate", "-g", action="store_true", help="gera a senha da entrada")
    add.add_argument("--length", type=int, default=20, help="tamanho da senha gerada")
    add.add_argument("--force", action="store_true", help="substitui uma entrada existente")
    get = commands.add_parser("get", help="mostra uma credencial")
    get.add_argument("name")
    get.add_argument("--show", "-s", action="store_true", help="mostra a senha em texto claro")
    commands.add_parser("list", help="lista nomes, usuários e datas")
    search = commands.add_parser("search", help="busca nomes sem diferenciar maiúsculas")
    search.add_argument("substring")
    commands.add_parser("count", help="imprime apenas o número de entradas")
    delete = commands.add_parser("delete", help="remove uma entrada")
    delete.add_argument("name")
    generate = commands.add_parser("gen", help="gera uma senha sem abrir o vault")
    generate.add_argument("length", type=int, nargs="?", default=20)
    commands.add_parser("change-password", help="troca a senha mestra")
    return parser


def _run(args: argparse.Namespace) -> None:
    if args.command == "gen":
        print(generate_password(args.length))
        return

    path = args.vault or Path(os.environ.get("PV_VAULT", "~/.password-vault/vault.json"))
    with Vault(path) as vault:
        if args.command == "init":
            vault.initialize(_new_master())
            print(f"Vault criado em {vault.path}")
            return

        vault.unlock(_master("Senha mestra atual: " if args.command == "change-password" else "Senha mestra: "))

        if args.command == "add":
            if args.name in vault.entries and not args.force:
                raise VaultError("entrada já existe; use --force para substituí-la")
            username = input("Usuário: ")
            password = generate_password(args.length) if args.generate else getpass.getpass("Senha da entrada: ")
            if not password:
                raise ValueError("senha da entrada não pode ser vazia")
            url = input("URL (opcional): ")
            notes = input("Notas (opcional): ")
            timestamp = now()
            vault.add(args.name, Entry(username, password, url, notes, timestamp, timestamp), args.force)
            print(f"Entrada salva: {args.name}")
        elif args.command == "get":
            entry = vault.get(args.name, touch=True)
            print(f"Nome: {_display(args.name)}")
            print(f"Usuário: {_display(entry.username)}")
            print(f"Senha: {_display(entry.password) if args.show else '********'}")
            print(f"URL: {_display(entry.url)}")
            print(f"Notas: {_display(entry.notes)}")
            print(f"Criada em: {_display(entry.created_at)}")
            print(f"Atualizada em: {_display(entry.updated_at)}")
            print(f"Último uso: {_display(entry.last_used_at)}")
        elif args.command == "list":
            for name in vault.names():
                entry = vault.entries[name]
                print(f"{_display(name)}\t{_display(entry.username)}\t{_display(entry.updated_at)}")
        elif args.command == "search":
            if not args.substring:
                raise ValueError("consulta de busca não pode ser vazia")
            for name in vault.names():
                if args.substring.casefold() in name.casefold():
                    print(_display(name))
        elif args.command == "count":
            print(len(vault.entries))
        elif args.command == "delete":
            vault.delete(args.name)
            print(f"Entrada removida: {args.name}")
        elif args.command == "change-password":
            vault.change_password(_new_master())
            print("Senha mestra alterada")


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    # `just run -- init` encaminha o separador literalmente para esta CLI.
    if arguments and arguments[0] == "--":
        arguments = arguments[1:]
    args = _parser().parse_args(arguments)
    try:
        _run(args)
        return 0
    except (VaultError, ValueError, OSError, EOFError, KeyboardInterrupt) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
