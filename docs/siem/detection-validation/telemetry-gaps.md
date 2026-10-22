# Lacunas de telemetria e melhorias de logging

Duas listas: o que **foi implementado** nesta entrega (com teste automatizado e validado na execução local) e o que
**continua pendente**, com proposta. Nada abaixo registra senhas, tokens, cookies ou corpo de requisição.

## Implementadas

| ID | Melhoria | Campo / evento novo | Testes beneficiados | Segurança do dado | Onde |
|---|---|---|---|---|---|
| G-01 | Referência opaca da sessão | `session_ref`: 16 hex do SHA-256 do cookie `SecureCorp.Auth`; só existe com cookie. Vai em **todas** as linhas da requisição, inclusive `UserLogin`/`UserLogout` | T-09 (de Não Detectável para Total); correlação de sessões em todos | Hash truncado e irreversível; o cookie nunca é gravado (teste confirma que o valor do cookie não aparece no log) | `CorrelationMiddleware` |
| G-02 | Cabeçalhos de origem | `origin`, `sec_fetch_site`, `referer` (sem query nem fragmento) | T-10, T-11 | `referer` perde query/fragmento (podem ter tokens); testado com `?token=…` | `CorrelationMiddleware` |
| G-03 | Falha de antiforgery auditada | `AccessDenied` com `action=csrf.validation_failed`, `resource=<path>` | T-10 (de Parcial para Total) | Sem dados do formulário | `AntiforgeryFailureAuditFilter` |
| G-04 | `X-Request-ID` rejeitado | `properties.request_id_rejected` (valor enviado, sem caracteres de controle, ≤ 64) | T-25 (de Não Detectável para Total) | Sanitizado por `LogSanitizer`; JSON escapa o restante | `CorrelationMiddleware` |
| G-05 | Tamanho do corpo | `content_length` | T-15 (10 MiB+1 não passa pela auditoria) | Só o número | `CorrelationMiddleware` |
| G-06 | Porta de origem | `source_port` | Atribuição de origem atrás de túnel SSH ([runbook §6](execution-runbook.md#6-ssh-port-forwarding)) | Só o número | `CorrelationMiddleware` |
| G-07 | Nome de arquivo enviado | `details` de `DocumentUploaded` ganha `Nome enviado pelo cliente: '…'` quando difere do nome gravado, e nas rejeições | T-14 (de Não Detectável para Total), T-12 | Truncado em 200 caracteres, sem controle | `DocumentService` |
| G-08 | Open redirect pós-login | `AccessDenied` com `action=login.external_return_url_blocked`, `resource=<returnUrl>` (≤ 256) | T-18 (de Parcial para Total) | URL fornecida pelo cliente, sanitizada pelo `AuditService` | `AccountController` |

Os campos novos estão no [esquema de logs](../log-schema.md); os eventos novos, no [catálogo](../event-catalog.md).
Cobertura por testes: `LogFileIntegrationTests` (5 casos: `request_id_rejected`, `session_ref` presente/ausente e sem vazar o cookie,
cabeçalhos de origem, antiforgery) e `AuditTrailTests` (nome enviado, `returnUrl` externo). Suíte: **204 testes, 204 aprovados**
no container `dotnet/sdk:8.0` (`docker compose --profile test run --rm tests`).

Preservação: nenhum campo existente mudou de nome ou de significado; as respostas HTTP continuam idênticas (o 400 de antiforgery
e o redirecionamento do login não mudaram). `AccountController` ganhou `IAuditService` no construtor.

## Pendentes

| ID | Lacuna | Testes | Proposta | Prioridade |
|---|---|---|---|---|
| G-P1 | O corpo (JSON/form) não é registrado: tentativas de mass assignment (`role`, `isAdmin`, `id`) e payloads XSS em POST são invisíveis | T-05, T-17, T-20 | (a) registrar só os **nomes** dos membros JSON não mapeados (nunca os valores) em um evento `UnmappedInput`; (b) evento `SuspiciousInput` com a **categoria** do padrão encontrado em campos de texto livre; (c) WAF/reverse proxy na frente. Exige ler/bufferizar o corpo ou ligar `UnmappedMemberHandling`, e por isso não foi feito sem autorização | Alta |
| G-P2 | Acesso a documento não registra o motivo (dono, classificação vs. papel); um 200 em recurso de terceiro é indistinguível de uso legítimo | T-01, T-02 | Acrescentar `access_reason` (`owner` / `classification`) e `owner_id` ao `DocumentAccessed`/`DocumentDownloaded` | Média |
| G-P3 | Leitura do diretório de usuários e do perfil de outros por ANALYST não é auditada (F-10) | T-03 | Evento `UserDirectoryViewed` (Low) em `GET /api/users` e `/users` | Baixa |
| G-P4 | `username` de login falho vai em claro para log e banco (F-09) | T-26 | Mascarar na origem quando o valor não casa com `^[A-Za-z0-9._-]{3,32}$` (guardar hash e tamanho); o SIEM só cobre parte (DR-19) | Média |
| G-P5 | Upload aceito não deixa nenhum indício de conteúdo suspeito (poliglota) | T-13 | Gravar o SHA-256 do arquivo no evento (para caça por hash) e avaliar varredura de conteúdo/antimalware | Média |
| G-P6 | `/error/{n}` aceita qualquer inteiro; `status_code` do log (0, 5000) diverge do que o cliente recebe e nenhuma exceção é registrada para `0` (F-12) | T-22 | Limitar a 100–599 em `ErrorController` (correção funcional, fora do escopo de logging) | Baixa |
| G-P7 | Cabeçalhos de resposta não são logados; teste passivo não deixa rastro | T-23 | Não é problema de SIEM: usar verificação sintética periódica (script/scanner) e alertar a regressão | Baixa |
| G-P8 | Sessão não é invalidada no logout (F-03): a regra DR-11 **detecta**, mas não impede | T-09 | `UpdateSecurityStampAsync` no logout (correção de segurança no código principal, dependente de autorização) | Alta |
| G-P9 | Sem rate limiting (F-02): spraying e bloqueio de conta de terceiros só são detectados, não contidos | T-07, T-08 | `AddRateLimiter` por IP em `/login`, `/register`, `/api/auth/*` (código principal) | Alta |
| G-P10 | `source_ip` atrás de túnel SSH / Docker Desktop não é o do atacante | todos | [Runbook §6](execution-runbook.md#6-ssh-port-forwarding): testar pela rede isolada ou correlacionar `source_port` com telemetria do host | Média |
| G-P11 | Integridade dos logs: arquivos graváveis pela aplicação e `audit_events` editável; só há valor se o coletor enviar rápido | todos | Enviar ao SIEM em tempo quase real; considerar tabela de auditoria append-only | Média |
| G-P12 | O evento de `PasswordChanged`/`UserUpdated` não registra o papel solicitado nem os valores anteriores | T-04 | Incluir `requested_role` nos `AccessDenied` de escalonamento | Baixa |

Itens G-P8 e G-P9 são **correções de vulnerabilidade**, não de logging: ficam fora do pedido e do escopo permitido (alteração do código principal além de telemetria).

## Cobertura resultante

| | Antes das melhorias | Depois |
|---|---|---|
| Total | 12 | 18 |
| Parcial | 10 | 8 |
| Não Detectável | 6 | 2 |

Reclassificações: T-09, T-14 e T-25 de Não Detectável para Total (G-01, G-07, G-04); T-11 de Não Detectável para Parcial (G-02);
T-10, T-18 e T-15 de Parcial para Total (G-03, G-08, G-05). T-17 e T-23 continuam sem telemetria; T-05 e T-20 seguem Parcial (G-P1).
A coluna "antes" é uma estimativa reconstruída a partir do código anterior, não uma medição.
