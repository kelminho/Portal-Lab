# Casos de detecção sugeridos

Limiares são pontos de partida para o laboratório; ajuste conforme o volume.
Salvo indicação, use `security-*.json`.

| # | Detecção | Lógica | Severidade sugerida |
|---|---|---|---|
| 1 | Força bruta | ≥ 5 `UserLoginFailed` com o mesmo `source_ip` e mesmo `username` em 5 min | Média |
| 2 | Password spraying | Mesmo `source_ip` com `UserLoginFailed` para ≥ 4 `username` distintos em 10 min | Alta |
| 3 | Enumeração de usuários | ≥ 3 `UserLoginFailed` com `properties.details = "Usuário inexistente."` do mesmo IP em 10 min | Média |
| 4 | Conta bloqueada | Qualquer `UserLockedOut` | Alta |
| 5 | Login após falhas | `UserLogin` do mesmo `username` e `source_ip` até 10 min após ≥ 3 `UserLoginFailed` | Crítica |
| 6 | Escalada de privilégio | Qualquer `RoleChanged`; mais grave se o novo papel for ADMIN | Alta |
| 7 | Acesso negado repetido | ≥ 5 `AccessDenied` do mesmo `username` em 10 min (enumeração de recursos/IDOR) | Média |
| 8 | Exfiltração | ≥ 10 `DocumentDownloaded` ou `DocumentAccessed` do mesmo `username` em 10 min | Média |
| 9 | Conta nova com atividade | `UserCreated` seguido de `AccessDenied` ou downloads em 30 min | Baixa |
| 10 | Exclusão de contas | Qualquer `UserDeleted` | Alta |
| 11 | Upload suspeito | `DocumentUploaded` com `outcome = failure` ≥ 3 do mesmo IP | Média |
| 12 | SQLi na busca | `HttpRequest` em `/search`, `/documents` ou `/api/documents` com `query_string` contendo `%27`, `--`, `union`, `select`, `or 1=1` (decodificar antes) | Alta |
| 13 | XSS refletido | `query_string` com `%3Cscript`, `onerror=`, `javascript:` | Alta |
| 14 | Path traversal | `query_string` ou `endpoint` com `../`, `..%2f`, `%2e%2e` | Alta |
| 15 | Varredura de diretórios | ≥ 30 `HttpRequest` com `status_code = 404` do mesmo IP em 2 min (`securecorp-*.json`) | Média |
| 16 | Ferramentas ofensivas | `user_agent` contendo `sqlmap`, `nikto`, `gobuster`, `hydra` | Baixa |
| 17 | Erros em série | ≥ 3 `ApplicationError` ou `status_code >= 500` do mesmo IP em 5 min | Alta |
| 18 | Integridade da auditoria | Qualquer `AuditPersistenceFailed` | Alta |
| 19 | Laboratório ativo | `SecurityLabEnabled` fora de janela planejada | Alta |
| 20 | Usuário × IP incomum | `UserLogin` do mesmo `username` a partir de ≥ 2 `source_ip` distintos em 1 h | Média |

## Correlação

- Use `request_id` para juntar `HttpRequest` + evento de auditoria da mesma requisição.
- Use `source_ip` + `username` para montar a linha do tempo de um ataque (falhas → sucesso → ações).

## Painéis úteis

- Logins falhos por IP e por `username` (top 10).
- Série temporal de `AccessDenied` e `UserLoginFailed`.
- Contagem de `HttpRequest` por `status_code` e por IP.
- Últimos `RoleChanged`, `UserDeleted`, `UserLockedOut`.
- `query_string` de `/search` com padrões suspeitos.

## Limites conhecidos (úteis para exercícios)

- Não há rate limiting: tentativas só são barradas pelo lockout de conta (5 falhas / 15 min).
- Spraying lento (abaixo do limiar de lockout por conta) só é detectável por correlação por IP.
- O corpo (POST) das requisições não é registrado; só método, caminho e query string.
