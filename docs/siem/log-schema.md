# Esquema dos logs

Formato **JSON Lines** (um objeto por linha, UTF-8), campos em `snake_case`.

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `logs/securecorp-AAAAMMDD.json` | Todos os eventos |
| `logs/security-AAAAMMDD.json` | Somente `event_category` = `audit` ou `security` |

Rotação diária, 14 arquivos retidos. O console pode emitir o mesmo JSON (`AppLogging__ConsoleFormat=json`).

## Campos sempre presentes

| Campo | Tipo | Descrição |
|---|---|---|
| `timestamp` | string | UTC, `yyyy-MM-ddTHH:mm:ss.fffZ` (mapear como timestamp do evento) |
| `level` | string | `Information`, `Warning`, `Error`, `Fatal` |
| `severity` | string | `info`, `low`, `medium`, `high`, `critical` |
| `message` | string | Texto renderizado, com dados sensíveis mascarados |
| `message_template` | string | Template da mensagem |
| `application` | string | `SecureCorpPortal` |
| `environment` | string | `Production` ou `Development` |
| `host` | string | Nome da máquina/container |

## Campos opcionais (nível superior)

| Campo | Tipo | Descrição |
|---|---|---|
| `event_type` | string | Ver [event-catalog.md](event-catalog.md) |
| `event_category` | string | `audit`, `security`, `http`, `application` |
| `action` | string | Ação lógica (ex.: `auth.login`) |
| `outcome` | string | `success` ou `failure` |
| `request_id` | string | Correlaciona todos os eventos de uma requisição (header `X-Request-ID`) |
| `source_ip` | string | IP da conexão (ou do `X-Forwarded-For`, se habilitado — ver integration-guide) |
| `source_port` | number | Porta de origem da conexão TCP. Atrás de túnel SSH identifica a conexão aberta pelo sshd (ver [runbook §6](detection-validation/execution-runbook.md#6-ssh-port-forwarding)) |
| `user_id` | number | Id do usuário autenticado |
| `username` | string | Usuário autenticado ou **tentado** em falhas de login |
| `http_method` | string | `GET`, `POST`... |
| `endpoint` | string | Caminho **sem** query string |
| `query_string` | string | Query bruta (codificada), sem `?`; valor de parâmetros sensíveis vira `[REDACTED]`; máx. 2048 caracteres |
| `status_code` | number | Só em `HttpRequest` |
| `duration_ms` | number | Só em `HttpRequest` |
| `user_agent` | string | Máx. 512 caracteres, sem caracteres de controle |
| `session_ref` | string | 16 hex do SHA-256 do cookie de sessão; identifica a sessão sem expor o cookie. Ausente sem cookie. Une login → requisições → logout |
| `origin` | string | Cabeçalho `Origin` (máx. 256) |
| `referer` | string | Cabeçalho `Referer` **sem query nem fragmento** (máx. 256) |
| `sec_fetch_site` | string | `same-origin`, `same-site`, `cross-site` ou `none` (enviado por navegadores, não por curl/Burp) |
| `content_length` | number | Tamanho declarado do corpo da requisição, em bytes |
| `resource` | string | Recurso afetado (ex.: documento) |
| `trace_id` | string | Trace W3C quando disponível |
| `source_context` | string | Classe que gerou o log |

## Objetos

- `properties`: demais campos do evento (ex.: `audit_id`, `details`, `request_id_rejected` — valor de `X-Request-ID` descartado por formato inválido, limpo e com ≤ 64 caracteres).
- `exception`: `type`, `message`, `stack_trace` (só em erros).

## Dados nunca registrados

Senhas, tokens, cookies e connection strings. Propriedades com nomes sensíveis e parâmetros de
query com esses nomes saem como `[REDACTED]`. O corpo (POST) das requisições não é registrado.

## Exemplos

Falha de login:

```json
{"timestamp":"2026-10-22T18:00:01.120Z","level":"Warning","severity":"medium","message":"Audit UserLoginFailed: auth.login [failure]","application":"SecureCorpPortal","host":"securecorp-web","event_type":"UserLoginFailed","event_category":"audit","action":"auth.login","outcome":"failure","request_id":"74e2340b29b74bcb97d58ca3f16f3ae9","source_ip":"192.168.56.20","username":"employee","http_method":"POST","endpoint":"/api/auth/login","user_agent":"curl/8.5.0","properties":{"audit_id":3,"details":"Senha inválida."}}
```

Requisição com payload suspeito:

```json
{"timestamp":"2026-10-22T18:02:11.300Z","level":"Information","severity":"info","message":"HTTP GET /api/documents respondeu 200 em 12.4 ms","event_type":"HttpRequest","event_category":"http","action":"http.request","request_id":"a1b2c3d4e5f6a7b8","source_ip":"192.168.56.20","user_id":3,"username":"employee","http_method":"GET","endpoint":"/api/documents","query_string":"q=%27%20OR%201%3D1--","status_code":200,"duration_ms":12.4}
```
