# Demonstração — Pass Vault

## Projeto e problema

O Pass Vault é um gerenciador local de credenciais por linha de comando. Ele permite
recuperar senhas de serviços quando necessário, mantendo as entradas criptografadas
em um arquivo. O cenário principal é o roubo de uma cópia desse arquivo: sem a senha
mestra, o atacante precisa tentar adivinhá-la para derivar a chave de abertura.

## O que foi implementado

Os comandos `init`, `add`, `get`, `list`, `delete`, `gen` e `change-password` formam a
base do programa. Os quatro desafios do MVP também estão presentes: `search`,
`count`, registro de último uso no `get` e senha ocultada por padrão, revelada com
`get --show`.

A senha mestra passa por Argon2id para produzir a chave. AES-256-GCM cifra as
entradas e verifica sua integridade. A cada gravação, o programa usa um nonce novo,
salva primeiro em um arquivo temporário, sincroniza os dados e substitui o arquivo
anterior. Um arquivo `.lock` serializa processos que acessam o mesmo vault.

## Resultados e validação

- `just test`: 82 testes aprovados no Windows; dois testes de permissões POSIX são
  ignorados nessa plataforma.
- `just lint`: Ruff, mypy e Pylint passaram.
- Os testes incluem abertura com senha incorreta, adulteração do arquivo, rotação
  da senha mestra, bloqueio entre processos e comportamento dos comandos da CLI.

## Decisões e limites

`argparse` mantém a interface pequena e sem dependências adicionais para a CLI.
Argon2id dificulta tentativas de senha mestra feitas sobre um arquivo roubado; ele
não compensa uma senha mestra fraca. A cifra autenticada rejeita alterações nos
dados, enquanto bloqueio e gravação atômica tratam concorrência e interrupções
durante o salvamento. São problemas diferentes, por isso exigem mecanismos
diferentes.

O projeto não protege contra keyloggers, observação da tela durante `get --show`
ou leitura da memória de um processo desbloqueado. No Windows, as permissões
dependem das ACLs herdadas do diretório e não há sincronização do diretório pela
biblioteca padrão. Esta é uma implementação educacional, não um substituto para
um gerenciador de senhas auditado.

## Conclusão

O exercício mostrou por que criptografar o conteúdo é apenas parte do problema:
é preciso também derivar bem a chave, autenticar o arquivo, evitar perda de dados
na gravação e definir explicitamente as ameaças cobertas. Um passo futuro seria
comparar essas decisões com as de um gerenciador de senhas auditado.

## Vídeo

**Link da demonstração:** https://www.youtube.com/watch?v=sNfWKOk18LE

### Diagrama 1 — abertura e proteção

```mermaid
flowchart LR
    M["Senha mestra digitada"] --> K["Argon2id"]
    S["Salt público"] --> K
    K --> C["Chave AES"]
    C --> A["AES-256-GCM"]
    P["Credenciais em JSON"] --> A
    N["Nonce novo"] --> A
    A --> V["Vault cifrado e autenticado"]
```

### Diagrama 2 — salvamento

```mermaid
flowchart LR
    L["Adquire .lock"] --> U["Lê e altera entradas"]
    U --> T["Grava temporário"]
    T --> F["fsync dos dados"]
    F --> R["os.replace"]
    R --> D["fsync do diretório em POSIX"]
    D --> X["Libera .lock"]
```