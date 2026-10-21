# logs/

Diretório onde a aplicação grava os logs estruturados (JSON Lines — um objeto JSON por linha).

| Arquivo | Conteúdo |
|---|---|
| `securecorp-AAAAMMDD.json` | Todos os eventos: requisições HTTP, auditoria, segurança, erros e ciclo de vida |
| `security-AAAAMMDD.json` | Somente eventos com `event_category` = `audit` ou `security` |

- Rotação diária, retenção padrão de 14 arquivos (`AppLogging:RetainedFileCountLimit`).
- No Docker, este diretório é montado em `/app/logs` do container `securecorp-web`.
- Executando com `dotnet run` (ambiente Development), os logs também são gravados aqui.
- Os arquivos `*.json` são ignorados pelo Git.

Formato dos campos: [`docs/siem/log-schema.md`](../docs/siem/log-schema.md).
