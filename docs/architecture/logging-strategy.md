# Estratégia de logging e auditoria

## Dois fluxos complementares

| | Log técnico (Serilog) | Trilha de auditoria (`AuditService`) |
|---|---|---|
| Destino | `logs/*.json` e console | Tabela `audit_events` **+** log JSON (`event_category=audit`) |
| Conteúdo | Toda requisição HTTP, erros, startup, eventos de segurança técnicos | Ações de negócio relevantes (login, papel alterado, documento acessado…) |
| Consumidor | SIEM, troubleshooting | Tela `/admin/logs`, API `/api/admin/logs`, SIEM |
| Retenção | Rotação diária, 14 arquivos | Permanente no banco |

Os dois compartilham o mesmo `request_id`, então é possível ir de um evento de auditoria para
todas as linhas técnicas da mesma requisição.

## Como um campo chega ao log

```
CorrelationMiddleware ── LogContext.PushProperty ──► request_id, source_ip/port, http_method, endpoint, query_string,
                                                     user_agent, session_ref, origin, referer, sec_fetch_site, content_length
RequestLoggingMiddleware ── LogContext.PushProperty ──► user_id, username  (usuário autenticado)
logger.BeginEventScope(...) ─────────────────────────► event_type, event_category, severity, action
AuditService (escopo) ───────────────────────────────► user_id/username do ator, resource, details, audit_id
Template da mensagem "… {status_code} …" ────────────► status_code, duration_ms, outcome…
                                   │
                                   ▼
                     SiemJsonFormatter (Logging/SiemJsonFormatter.cs)
                       • campos conhecidos → nível superior, nomes fixos
                       • demais propriedades → "properties"
                       • nomes sensíveis → "[REDACTED]"
                       • severity: explícita ou derivada do nível
                                   │
                ┌──────────────────┴───────────────────┐
                ▼                                      ▼
     logs/securecorp-AAAAMMDD.json          logs/security-AAAAMMDD.json
     (todos os eventos)                     (event_category = audit | security)
```

## Níveis de log e severidade

`level` é o nível do Serilog; `severity` é a escala usada pelo SOC.

| Situação | level | severity |
|---|---|---|
| Requisição 2xx/3xx/404 | Information | info |
| Requisição 401/403 | Warning | medium |
| Requisição 5xx / exceção | Error | high |
| Evento de auditoria | conforme severidade | definida em `AuditSeverityDefaults` (info → critical) |

Níveis mínimos por namespace ficam em `appsettings.json` → `Serilog:MinimumLevel`
(ruído do ASP.NET Core e do EF Core é reduzido para `Warning`).

## O que NUNCA é registrado

- Senhas (inclusive tentativas erradas), hashes, security stamps;
- Cookies, tokens antiforgery, cabeçalho `Authorization` (do cookie de sessão só se grava `session_ref`, um hash truncado e irreversível);
- Connection strings e segredos de configuração;
- Corpo das requisições. A `query_string` é registrada (parâmetros com nome sensível saem `[REDACTED]`) e o `referer` perde query e fragmento.

Proteções:
1. **Por design**: nenhum código passa esses valores ao logger; DTOs com senha nunca são logados.
2. **Defesa em profundidade**: `SensitiveData.IsSensitiveKey` mascara propriedades cujo nome contenha
   `password`, `token`, `secret`, `cookie`, `authorization`, `credential`, `connectionstring`…,
   em qualquer nível de objetos aninhados e na mensagem renderizada.
3. **Contra forja de linhas**: valores vindos do usuário passam por `LogSanitizer.Clean`
   (remove caracteres de controle e limita o tamanho), e o JSON escapa quebras de linha.
4. **Testes** (`tests/.../Logging` e `Audit`) verificam que senhas não aparecem nos arquivos nem no banco.

## Onde adicionar um novo evento

- **Evento de negócio** → `await _audit.RecordAsync(new AuditEntry(AuditEventType.X, "recurso.acao") { ... })`.
  Se for um tipo novo, adicione ao enum `AuditEventType`, a `AuditSeverityDefaults` e ao
  [catálogo de eventos](../siem/event-catalog.md).
- **Evento técnico** →
  ```csharp
  using (_logger.BeginEventScope("NomeDoEvento", EventCategories.Security, severity: "medium"))
  {
      _logger.LogWarning("Descrição com {campo_estruturado}", valor);
  }
  ```
  Use nomes de propriedade em `snake_case` e prefira constantes de `LogFields`.
