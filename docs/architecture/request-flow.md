# Fluxo de uma requisição

## Pipeline de middlewares (`Program.cs`)

A ordem importa: cada middleware só "enxerga" o que foi preparado pelos anteriores.

| # | Middleware | O que faz | Por que nesta posição |
|---|---|---|---|
| 1 | `CorrelationMiddleware` | Define `request_id` (aceita `X-Request-ID` válido ou gera um), devolve no header e adiciona `request_id`, `source_ip`, `http_method`, `endpoint`, `user_agent` ao contexto de log | Primeiro: **todo** log posterior (inclusive de erros) carrega esses campos |
| 2 | `UseExceptionHandler("/error")` + `GlobalExceptionHandler` | Captura exceções não tratadas, registra `ApplicationError` e responde de forma genérica (JSON na API, página `/error` no MVC) | Antes de tudo que pode falhar |
| 3 | `UseStatusCodePagesWithReExecute("/error/{0}")` | Transforma respostas 403/404 sem corpo em página amigável (ou ProblemDetails para `/api`) | Envolve o restante do pipeline |
| 4 | `SecurityHeadersMiddleware` | CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`… | Vale também para arquivos estáticos e páginas de erro |
| 5 | `UseStaticFiles` | Serve `wwwroot` (CSS/JS) | Antes da autenticação: estáticos não precisam de usuário |
| 6 | `UseRouting` | Escolhe o endpoint (controller/action) | Necessário antes da autorização |
| 7 | `UseAuthentication` | Lê o cookie e preenche `HttpContext.User` | Antes do log de requisição, para saber quem é o usuário |
| 8 | `RequestLoggingMiddleware` | Ao final, registra `HttpRequest` com `status_code`, `duration_ms`, `user_id`, `username` | Depois da autenticação, envolvendo a autorização e o controller |
| 9 | `UseAuthorization` | Aplica `[Authorize]`, policies e fallback policy | Logo antes do endpoint |
| 10 | Endpoint | Controller → Service → Repository → banco | — |

## Fluxo: login com sucesso (API)

```
POST /api/auth/login {"userName":"analyst","password":"***"}
 │
 ├─ CorrelationMiddleware      request_id = 9f2c…  (header X-Request-ID na resposta)
 ├─ Authentication             usuário anônimo
 ├─ Authorization              [AllowAnonymous] → segue
 ├─ AuthApiController.Login    valida o DTO ([ApiController] → 400 se inválido)
 ├─ AuthService.LoginAsync
 │    ├─ UserManager.FindByNameAsync("analyst")
 │    ├─ verifica IsActive
 │    ├─ SignInManager.PasswordSignInAsync(lockoutOnFailure: true)  → emite cookie SecureCorp.Auth
 │    ├─ atualiza LastLoginAt
 │    └─ AuditService.RecordAsync(UserLogin)
 │          ├─ INSERT em audit_events (DbContext próprio)
 │          └─ log JSON: event_type=UserLogin, event_category=audit, outcome=success
 ├─ 200 {"message":"Login realizado com sucesso.","user":{...}}
 └─ RequestLoggingMiddleware   log JSON: event_type=HttpRequest, status_code=200, duration_ms=…
```

## Fluxo: acesso negado por papel (policy)

```
GET /api/admin/logs   (usuário EMPLOYEE autenticado)
 ├─ Authorization: policy AdminOnly falha → Forbid()
 ├─ Cookie OnRedirectToAccessDenied (AuthenticationEventHandlers)
 │    ├─ AuditService: AccessDenied, action=authorization.policy_denied, resource=/api/admin/logs
 │    └─ /api → 403 application/problem+json   |   página → 302 /access-denied
 └─ RequestLoggingMiddleware: HttpRequest status_code=403 (level Warning)
```

## Fluxo: acesso negado por recurso (documento)

```
GET /documents/9   (GUEST; documento Restricted)
 ├─ Authorization: [Authorize] ok (usuário autenticado)
 ├─ DocumentsController.Details → DocumentService.GetAsync
 │    ├─ DocumentRepository.GetByIdAsync(9)
 │    ├─ DocumentAccessPolicy.CanRead(GUEST, Restricted) = false
 │    ├─ AuditService: AccessDenied, action=document.read_denied, resource=document:9
 │    └─ ServiceResult.Forbidden
 ├─ Controller → StatusCode(403)
 ├─ StatusCodePages re-executa /error/403 → página "Acesso negado" com request_id
 └─ RequestLoggingMiddleware: HttpRequest status_code=403
```

## Fluxo: upload de arquivo

```
POST /documents/upload (multipart, token antiforgery)
 ├─ [AutoValidateAntiforgeryToken] valida o token CSRF
 ├─ [RequestSizeLimit 10 MB] limita o corpo antes do model binding
 ├─ policy CanCreateDocuments (ADMIN/ANALYST/EMPLOYEE)
 ├─ DocumentService.UploadAsync
 │    ├─ DocumentAccessPolicy.CanCreate (classificação ≤ nível do papel)
 │    ├─ LocalFileStorageService.Validate: tamanho, extensão permitida, assinatura binária
 │    │     └─ rejeitado → DocumentUploaded (success=false) + 400
 │    ├─ SaveAsync: nome aleatório (GUID), fora de wwwroot
 │    ├─ INSERT em documents
 │    └─ AuditService: DocumentUploaded (nome, tamanho, content-type)
 └─ 302 → /documents/{id}
```

## Fluxo: exceção não tratada

```
Exceção em qualquer ponto após o passo 2
 ├─ GlobalExceptionHandler: log Error, event_type=ApplicationError, exception{type,message,stack_trace}
 ├─ /api → 500 ProblemDetails {"title":"Erro interno.","request_id":"…"} (sem stack trace)
 └─ página → /error com o request_id para o usuário informar ao suporte
```
