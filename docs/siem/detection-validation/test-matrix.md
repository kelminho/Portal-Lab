# Matriz de validação de detecção — T-01 a T-28

Cada linha parte de um teste de [`security-test-instructions.md`](../../architecture/security-test-instructions.md#7-matriz-de-testes-manuais)
e registra o que o **código e a execução real** mostraram, não o que a documentação previa.
Evidências: [`evidence/20261022T210231Z/`](evidence/20261022T210231Z/) (execução local de 22/10/2026 UTC, 404 expectativas, todas confirmadas nos logs).

> **Escopo da validação.** Tudo abaixo é **validação local** (o evento existe no log do portal).
> A ingestão e o disparo das regras no Falcon NG-SIEM **não foram testados**: nenhum acesso ao tenant.
> O status final de cada teste, portanto, é `NOT TESTED` (ver [`results/validation-results.csv`](results/validation-results.csv)).
> As regras CQL de [`detection-rules.md`](detection-rules.md) são propostas, não executadas.

## Como ler

**Detectabilidade** (do comportamento do ataque, com a telemetria atual):
- **Total** — a tentativa e o resultado (bloqueio/sucesso) aparecem em eventos distintos.
- **Parcial** — a tentativa aparece, mas o resultado ou parte das variantes não.
- **Não Detectável** — o ataque não deixa evento próprio.

**Estados de resultado** (qual assinatura de log corresponde a cada um — usada na linha *Estados* de cada teste):

| Estado | Como se reconhece nos logs |
|---|---|
| Tentativa identificada | `HttpRequest` (ou evento de auditoria) com o padrão do ataque |
| Bloqueada pela aplicação | `AccessDenied`, `UserLoginFailed`/`UserLockedOut`, `DocumentUploaded` com `outcome=failure`, ou `HttpRequest` 4xx |
| Possível exploração | Evento de sucesso (`outcome=success` / `HttpRequest` 2xx) em contexto anômalo (volume, ordem, ator) |
| Exploração confirmada | Só existe quando um evento prova o efeito (ex.: `RoleChanged` por ator não-admin, `session_ref` reutilizado após `UserLogout`) |
| Falha de detecção / sem telemetria | Nenhum evento distingue o ataque do uso legítimo |

Campos comuns a todos os eventos: `timestamp`, `request_id`, `source_ip`, `source_port`, `user_agent`, `username`/`user_id` (quando autenticado), `session_ref`.
`request_id` dos testes segue `PT-<teste>-<RUN_ID>-<seq>` (ex.: `PT-T07-20261022T210231Z-091`).

## Resumo

| ID | Categoria | Endpoint | Evento esperado | Sev. | Detectab. | Regras | Local |
|---|---|---|---|---|---|---|---|
| T-01 | IDOR / enumeração | `GET /api/documents/{id}` | `AccessDenied document.read_denied` | Medium | Total | DR-06, DR-07 (DR-24 em varreduras maiores) | PASS |
| T-02 | IDOR em arquivo | `GET /documents/{id}/download` | `AccessDenied document.download_denied` | Medium | Total | DR-06, DR-07 | PASS |
| T-03 | IDOR em usuários | `GET /api/users/{id}` | `AccessDenied user.read_denied` | Medium | Total | DR-06 | PASS |
| T-04 | Escalonamento vertical | `PUT /api/users/{id}` | `AccessDenied user.privilege_change_denied` / `user.update_denied` | High | Total | DR-08, DR-09 | PASS |
| T-05 | Mass assignment | `PUT /api/users/{id}` | `AccessDenied user.privilege_change_denied` (só se houver `isActive`/`role`) | High | Parcial | DR-08 | PARTIAL |
| T-06 | BFLA / matriz de papéis | `/admin/*`, `/api/admin/*`, `/users`, `/documents/upload` | `AccessDenied authorization.policy_denied` | Medium | Total | DR-10 | PASS |
| T-07 | Força bruta / lockout | `POST /api/auth/login` | 4× `UserLoginFailed` + `UserLockedOut` | High | Total | DR-01, DR-02, DR-05 | PASS |
| T-08 | Password spraying | `POST /api/auth/login` | N× `UserLoginFailed` (mesmo IP, N usuários) | High | Total | DR-03 | PASS |
| T-09 | Sessão após logout | `POST /api/auth/logout` + replay | `UserLogout` + `HttpRequest` 200 com o mesmo `session_ref` | High | Total | DR-11 | PASS |
| T-10 | CSRF (MVC) | `POST /login` sem token | `AccessDenied csrf.validation_failed` | Medium | Total | DR-16a | PASS |
| T-11 | CSRF (API) | `POST /api/documents/upload` cross-site | `DocumentUploaded` + `origin`/`sec_fetch_site` | Medium | Parcial | DR-16b | PARTIAL |
| T-12 | Upload: tipo | `POST /api/documents/upload` | `DocumentUploaded outcome=failure` | Medium | Total | DR-12, DR-13 | PASS |
| T-13 | Upload: conteúdo | idem | `DocumentUploaded failure` (sem `%PDF`); poliglota **aceito** | Medium | Parcial | DR-12 | PARTIAL |
| T-14 | Path traversal em nome | idem | `DocumentUploaded` com `Nome enviado pelo cliente: '../..'` | Medium | Total | DR-13 | PASS |
| T-15 | Limites de upload | idem | `DocumentUploaded failure` (5 MiB+1); só `HttpRequest` 400 (10 MiB+1) | Low | Total | DR-12, DR-14 | PASS |
| T-16 | Injection / XSS refletido | `GET /search`, `/documents`, `/api/documents` | `HttpRequest` com `query_string` | Medium | Parcial | DR-15 | PARTIAL |
| T-17 | XSS armazenado | `POST /api/documents` | `DocumentCreated` (payload invisível) | — | Não Detectável | — | NOT SUPPORTED |
| T-18 | Open redirect | `POST /login` `returnUrl` | `AccessDenied login.external_return_url_blocked` | Medium | Total | DR-17 | PASS |
| T-19 | Enumeração no cadastro | `POST /api/auth/register` | `UserCreated failure` (`DuplicateUserName`/`DuplicateEmail`) | Low | Total | DR-18 | PASS |
| T-20 | Mass assignment (cadastro) | `POST /api/auth/register` | `UserCreated success` papel GUEST (campo `role` invisível) | Low | Parcial | DR-18 | PARTIAL |
| T-21 | Enumeração por tempo | `POST /api/auth/login` | `UserLoginFailed` com `details` distintos; `duration_ms` | Low | Parcial | DR-04 | PARTIAL |
| T-22 | Tratamento de erros | `/error/{n}` | `HttpRequest` com `status_code` 0 / 5000 | Low | Parcial | DR-21 | PARTIAL |
| T-23 | Cabeçalhos / misconfig | qualquer página | nenhum (teste passivo) | — | Não Detectável | — | NOT SUPPORTED |
| T-24 | Consistência 401/403/404 | `/api/foo`, rota inexistente | `AuthenticationRequired`, `AccessDenied`, `HttpRequest` 404 | Low | Total | DR-10, DR-22 | PASS |
| T-25 | `X-Request-ID` forjado | qualquer | `HttpRequest` com `properties.request_id_rejected` | Low | Total | DR-20 | PASS |
| T-26 | Dado sensível no username | `POST /api/auth/login` | `UserLoginFailed` com o texto digitado em `username` | Medium | Parcial | DR-19 | PARTIAL |
| T-27 | Auditoria da auditoria | `/admin/logs`, `/api/admin/logs` | `AdminAction audit_log.viewed` | Info | Total | DR-23 | PASS |
| T-28 | Unlock por não-admin | `POST /admin/users/{id}/unlock` | `AccessDenied authorization.policy_denied` | Medium | Total | DR-10 | PASS |

**Cobertura local de telemetria:** 18 Total · 8 Parcial · 2 Não Detectável (de 28). Detalhes das lacunas em [`telemetry-gaps.md`](telemetry-gaps.md).
**Cobertura de detecção no SIEM validada:** 0/28 (NOT TESTED).

> Divergências entre o documento de testes e o comportamento real, encontradas ao validar:
> - T-07: a 5ª falha gera `UserLockedOut`, não `UserLoginFailed` (são 4 + 1, não 5 + 1). A 6ª tentativa, com a senha **correta**, gera outro `UserLockedOut`.
> - T-04: contra o ID de **outro** usuário o evento é `user.update_denied` (Medium); `user.privilege_change_denied` (High) só ocorre no próprio ID.
> - T-28: a negação **é** auditada (`authorization.policy_denied`, pela policy `AdminOnly` do controller); o service nunca chega a ser chamado.
> - T-15: 10 MiB + 1 retorna 400 (não 413) e não gera evento de auditoria.
> - T-09/F-03 e T-26/F-09 confirmados; T-21/F-11 com indício (ver T-21); T-22/F-12 confirmado em parte.

---

## T-01 — IDOR / enumeração de documentos

| Campo | Conteúdo |
|---|---|
| Endpoint | `GET /api/documents/{id}` (ids 1–15 e 9999, como `employee`) |
| MITRE ATT&CK | T1213 Data from Information Repositories (aproximada; ATT&CK não modela IDOR) |
| Comportamento | Varredura sequencial de IDs comparando 200, 403 e 404 |
| Evento esperado | 200 → `DocumentAccessed document.read`. 403 → `AccessDenied document.read_denied` (`resource=document:N`, `details` com a classificação). 404 → somente `HttpRequest` |
| Observado | 6× 200, 5× 403, 5× 404 (ids 12–15 e 9999 inexistentes) |
| Campos | `event_type`, `action`, `outcome`, `resource`, `username`, `source_ip`, `request_id`, `endpoint`, `status_code` |
| Regras | DR-06 (negações em recursos distintos), DR-07 (varredura de IDs). DR-24 (acesso em massa) não dispara com 6 leituras; vale para varreduras maiores |
| Severidade | Medium (High se DR-06 e DR-07 dispararem juntas) |
| Detectabilidade | Total |
| Lacunas | Não há motivo da autorização (`dono` / `classificação`) no evento de sucesso: um 200 em documento de terceiro é indistinguível de acesso legítimo. 404 não gera auditoria (só `HttpRequest`) |
| Validação | Buscar `request_id=/^PT-T01-<RUN>-/`: 16 `HttpRequest`; DR-06 deve alertar `employee` com 5 recursos distintos; DR-07 com 16 caminhos distintos |
| Estados | Tentativa: `HttpRequest /api/documents/N`. Bloqueada: `AccessDenied`. Possível exploração: `DocumentAccessed` em sequência (DR-24). Confirmada: não há evidência possível. Falha: 404 isolados sem regra |

## T-02 — IDOR em download de arquivo

| Campo | Conteúdo |
|---|---|
| Endpoint | `GET /documents/{id}/download` (também `GET /api/documents/{id}/download`) |
| MITRE | T1213 (aproximada) |
| Comportamento | `employee` e `guest` baixam documentos acima da classificação, incluindo um `Restricted` com arquivo criado pelo admin na preparação |
| Evento esperado | 403 → `AccessDenied document.download_denied`. Sucesso → `DocumentDownloaded document.download` |
| Observado | `employee`: 403 nos ids 7–11, 404 nos demais. `guest`: 403 também em 4–6. Documentos do seed não têm arquivo, então não há `DocumentDownloaded` nesta bateria (o evento foi confirmado em T-13) |
| Campos | idem T-01 |
| Regras | DR-06, DR-07 |
| Severidade | Medium |
| Detectabilidade | Total |
| Lacunas | Mesma de T-01. A ordem das checagens faz documentos inexistentes e sem arquivo responderem 404, e acima da permissão 403: oráculo de existência (F-08) visível apenas pela combinação de status |
| Validação | `request_id=/^PT-T02-<RUN>-/`: 32 requisições, 15 `AccessDenied`; DR-06 alerta `employee` e `guest` |
| Estados | Tentativa: `HttpRequest /documents/N/download`. Bloqueada: `AccessDenied`. Possível exploração/confirmada: `DocumentDownloaded` de documento de classificação acima do papel (nenhum nesta execução) |

## T-03 — IDOR em usuários

| Campo | Conteúdo |
|---|---|
| Endpoint | `GET /api/users/{id}` como `employee` (ids 1, 2, 9999 e o próprio 3) |
| MITRE | T1087 Account Discovery (aproximada) |
| Comportamento | Pedir dados de outro usuário e de ID inexistente |
| Evento esperado | `AccessDenied user.read_denied` (`resource=user:N`) |
| Observado | 403 para ids 1, 2 e 9999 (autorização antes da busca, sem oráculo de existência); 200 para o próprio id, **sem** evento de auditoria |
| Campos | `event_type`, `action`, `resource`, `username`, `source_ip` |
| Regras | DR-06 (DR-07 não dispara: só 4 caminhos) |
| Severidade | Medium |
| Detectabilidade | Total |
| Lacunas | Leitura permitida do diretório (`GET /api/users` por ADMIN/ANALYST) e de perfil alheio por ANALYST não é auditada (F-10) |
| Validação | `PT-T03-<RUN>-*`: 3 `AccessDenied` (`user:2`, `user:1`, `user:9999`); DR-06 dispara com exatamente 3 recursos distintos |
| Estados | Tentativa/bloqueada: `AccessDenied`. Exploração: leitura por ANALYST sem evento (lacuna F-10) |

## T-04 — Escalonamento vertical de privilégio

| Campo | Conteúdo |
|---|---|
| Endpoint | `PUT /api/users/{id}` com `{"role":"ADMIN"}` como `employee` |
| MITRE | T1068 Exploitation for Privilege Escalation (aproximada) |
| Comportamento | Enviar o papel desejado no próprio id e no id de outro usuário |
| Evento esperado | Próprio id → `AccessDenied user.privilege_change_denied` (**High**). Outro id → `AccessDenied user.update_denied` (Medium). Sucesso (por admin) → `RoleChanged` (High) |
| Observado | 403 nos dois casos; nenhum `RoleChanged` |
| Campos | `event_type`, `action`, `resource`, `username`, `properties.details` |
| Regras | DR-08 (tentativa bloqueada), DR-09 (`RoleChanged` por ator fora da lista de admins) |
| Severidade | High |
| Detectabilidade | Total |
| Lacunas | O evento não traz o papel solicitado (só o texto fixo em `details`) |
| Validação | `PT-T04-<RUN>-*`: 2 `AccessDenied`, uma High e uma Medium; nenhum `RoleChanged` |
| Estados | Tentativa/bloqueada: `AccessDenied`. Exploração confirmada: `RoleChanged ... para ADMIN` cujo `username` não está na lista de admins (DR-09) |

## T-05 — Mass assignment em perfil

| Campo | Conteúdo |
|---|---|
| Endpoint | `PUT /api/users/{id}` como `employee` |
| MITRE | T1190 Exploit Public-Facing Application (aproximada) |
| Comportamento | (a) `{"isActive":false,"id":1,"securityStamp":"x"}`; (b) `{"isAdmin":true,"id":1,"emailConfirmed":true}` |
| Evento esperado | (a) `AccessDenied user.privilege_change_denied`. (b) nenhum: propriedades desconhecidas são ignoradas |
| Observado | (a) 403 + evento. (b) **200 sem nenhum evento de auditoria** (nem `UserUpdated`, nem `AccessDenied`) |
| Campos | `event_type`, `action`, `username` |
| Regras | DR-08 (só cobre o caso (a)) |
| Severidade | High (a) / — (b) |
| Detectabilidade | Parcial |
| Lacunas | O corpo não é registrado, então tentar `isAdmin`, `id` ou `securityStamp` não deixa rastro. Proposta: registrar apenas os **nomes** dos membros JSON não mapeados (G-P1 em [`telemetry-gaps.md`](telemetry-gaps.md)) |
| Validação | `PT-T05-<RUN>-*`: um `AccessDenied` e um `HttpRequest` 200 sem evento associado |
| Estados | Tentativa (b): invisível. Bloqueada (a): `AccessDenied`. Exploração: estado inalterado (controle OK), mas sem prova em log |

## T-06 — BFLA / matriz de papéis

| Campo | Conteúdo |
|---|---|
| Endpoint | `/admin`, `/admin/users`, `/admin/logs`, `/api/admin/users`, `/api/admin/logs`, `/users`, `/api/users`, `/documents/upload` com `guest`, `employee`, `analyst` |
| MITRE | T1190 (aproximada: forced browsing) |
| Comportamento | Cada rota com cada papel |
| Evento esperado | Negação → `AccessDenied authorization.policy_denied` (`resource=<path>`) |
| Observado | 24 requisições, 20 negadas, todas com evento. Páginas MVC: 302 → `/access-denied`; API: 403. Permitidos: `employee` em `/documents/upload`; `analyst` em `/users`, `/api/users`, `/documents/upload` |
| Campos | `event_type`, `action`, `resource`, `username`, `source_ip` |
| Regras | DR-10 |
| Severidade | Medium (High se ≥ 4 recursos distintos) |
| Detectabilidade | Total |
| Lacunas | O evento não diz **qual policy** negou (texto fixo). O papel do ator não está no log |
| Validação | `PT-T06-<RUN>-*`: 20 `AccessDenied`; DR-10 alerta `guest` (8), `employee` (7) e `analyst` (5) |
| Estados | Tentativa: `HttpRequest` 302/403 em `/admin*`. Bloqueada: `AccessDenied`. Exploração: `HttpRequest` 200 em rota restrita por ator sem o papel (nenhuma) |

## T-07 — Força bruta e lockout

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/auth/login` |
| MITRE | T1110.001 Password Guessing |
| Comportamento | Conta dedicada `pt.lock.<RUN>`: 5 senhas erradas, depois a correta |
| Evento esperado | 4× `UserLoginFailed auth.login` (`details="Senha inválida."`); 5ª: `UserLockedOut auth.lockout` (High); 6ª (senha correta): 401 e novo `UserLockedOut` |
| Observado | Exatamente como acima (ver nota de divergência no resumo) |
| Campos | `event_type`, `action`, `outcome`, `username`, `source_ip`, `user_agent`, `properties.details` |
| Regras | DR-01 (≥ 5 eventos `UserLoginFailed`+`UserLockedOut` por IP e conta), DR-02. DR-05 (sucesso após falhas) não é exercitada por este teste |
| Severidade | High |
| Detectabilidade | Total |
| Lacunas | Não há campo que diga se a senha da 6ª tentativa estava correta; "login correto durante bloqueio" só se infere pelo `UserLockedOut` repetido |
| Validação | `PT-T07-<RUN>-*`: contar 4 + 2; DR-01 dispara com 6 eventos na janela de 5 min |
| Estados | Tentativa: `UserLoginFailed`. Bloqueada: `UserLockedOut`. Possível exploração: `UserLogin` do mesmo `username` após ≥ 3 falhas (DR-05). Confirmada: `UserLogin` do mesmo IP após falhas |

## T-08 — Password spraying

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/auth/login` |
| MITRE | T1110.003 Password Spraying |
| Comportamento | Uma senha errada contra as 6 contas de seed, mesmo IP e `user_agent` |
| Evento esperado | 6× `UserLoginFailed` (`details="Senha inválida."`), sem bloqueio por IP (F-02) |
| Observado | 6 eventos, 6 `username` distintos, nenhum `UserLockedOut` |
| Campos | `source_ip`, `user_agent`, `username`, `event_type`, `properties.details` |
| Regras | DR-03 (≥ 4 usuários distintos por IP em 10 min) |
| Severidade | High |
| Detectabilidade | Total (por correlação; a aplicação não bloqueia) |
| Lacunas | Atrás de túnel SSH o `source_ip` é o do túnel: agrupe por `user_agent` também (ver [runbook §6](execution-runbook.md#6-ssh-port-forwarding)) |
| Validação | `PT-T08-<RUN>-*`: 6 eventos; DR-03 alerta 1 IP com 6 usuários |
| Estados | Tentativa e bloqueio por senha: `UserLoginFailed`. Exploração: `UserLogin` posterior no mesmo IP para qualquer das contas |

## T-09 — Sessão após logout (F-03)

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/auth/logout`, depois `GET /api/auth/me` com o cookie guardado |
| MITRE | T1550.004 Use Alternate Authentication Material: Web Session Cookie |
| Comportamento | Login, cópia do cookie, logout, replay do cookie copiado |
| Evento esperado | `UserLogout auth.logout` e depois `HttpRequest` 200 com o **mesmo `session_ref`** |
| Observado | Logout 204. Replay **200**: a sessão não é invalidada no servidor (F-03 **confirmado**). `session_ref` do replay igual ao do `UserLogout` |
| Campos | `session_ref`, `event_type`, `status_code`, `endpoint`, `username`, `timestamp` |
| Regras | DR-11 |
| Severidade | High |
| Detectabilidade | Total (depende do campo `session_ref`, adicionado nesta entrega; antes, **Não Detectável**) |
| Lacunas | `session_ref` muda se o cookie for renovado por sliding expiration; replay de cookie renovado antes do logout não casa. Não registra o cookie (só hash truncado) |
| Validação | `PT-T09-<RUN>-*`: `UserLogout` (-106) e `HttpRequest` 200 (-107) com o mesmo `session_ref`; DR-11 alerta |
| Estados | Tentativa/possível exploração: `HttpRequest` 2xx após `UserLogout` no mesmo `session_ref`. Confirmada: idem, com `source_ip`/`user_agent` diferentes do login. Bloqueada: 401 (comportamento seguro, ainda não existente) |

## T-10 — CSRF em formulário MVC

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /login` sem token antiforgery |
| MITRE | Sem correspondência direta no ATT&CK (CSRF) |
| Comportamento | `curl -d` sem cookie/token |
| Evento esperado | `AccessDenied csrf.validation_failed` (`resource=/login`) + `HttpRequest` 400 |
| Observado | 400 com o evento (novo; antes só `HttpRequest` 400, indistinguível de erro de validação) |
| Campos | `event_type`, `action`, `resource`, `source_ip`, `user_agent`, `status_code` |
| Regras | DR-16a |
| Severidade | Medium |
| Detectabilidade | Total |
| Lacunas | A API (`/api/*`) não valida antiforgery (F-04): não existe evento a gerar |
| Validação | `PT-T10-<RUN>-001`: 1 `AccessDenied csrf.validation_failed` |
| Estados | Tentativa e bloqueio: mesmo evento. Exploração: n/a (400 impede) |

## T-11 — CSRF na API de upload (F-04)

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/documents/upload` com `Origin: http://localhost:9999` e `Sec-Fetch-Site: same-site` |
| MITRE | Sem correspondência direta |
| Comportamento | Upload multipart autenticado com cabeçalhos de outra origem do mesmo site. **Forjado com curl**: não prova o comportamento do navegador com `SameSite=Strict` |
| Evento esperado | `DocumentUploaded` (success) e `HttpRequest` 201 com `origin`, `sec_fetch_site`, `referer` (sem query) |
| Observado | 201 e os três campos presentes nos dois eventos |
| Campos | `origin`, `sec_fetch_site`, `referer`, `http_method`, `status_code`, `username` |
| Regras | DR-16b |
| Severidade | Medium |
| Detectabilidade | Parcial |
| Lacunas | Navegadores enviam `Sec-Fetch-Site`; ferramentas (curl, Burp) não: a ausência não prova nada. Atacante controla os cabeçalhos. Teste em navegador real **pendente** |
| Validação | `PT-T11-<RUN>-*`: `HttpRequest` 201 com `sec_fetch_site=same-site`; DR-16b alerta |
| Estados | Tentativa: POST com `sec_fetch_site` ≠ `same-origin`/`none`. Bloqueada: 4xx. Possível exploração: 2xx. Confirmada: não há como provar que o usuário não iniciou a ação |

## T-12 — Upload: tipos proibidos

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/documents/upload` |
| MITRE | T1190 (T1505.003 Web Shell, se um executável fosse aceito) |
| Comportamento | `.exe` (com `MZ`), `.html`, `.svg`, `.docm` e um `MZ` renomeado `.pdf` |
| Evento esperado | `DocumentUploaded document.upload` `outcome=failure`, `details="Upload rejeitado: … (extensão '.exe', N bytes). Nome enviado pelo cliente: '…'"` |
| Observado | 5× 400 com o evento |
| Campos | `event_type`, `outcome`, `username`, `source_ip`, `properties.details` |
| Regras | DR-12 (rajada de rejeições), DR-13 (extensão perigosa, 1 ocorrência) |
| Severidade | Medium |
| Detectabilidade | Total |
| Lacunas | O evento não traz o hash do arquivo (G-P5) |
| Validação | `PT-T12-<RUN>-*`: 5 `DocumentUploaded failure`; DR-13 alerta em 4 (`.exe`, `.html`, `.svg`, `.docm`; o `MZ` renomeado `.pdf` só cai em DR-12); DR-12 alerta o conjunto |
| Estados | Tentativa e bloqueio: `DocumentUploaded failure`. Exploração: `DocumentUploaded success` com extensão da lista de DR-13 (nenhuma) |

## T-13 — Upload: conteúdo vs extensão

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/documents/upload` |
| MITRE | T1190 |
| Comportamento | `.pdf` sem `%PDF`; `.png` com assinatura PNG seguida de HTML (poliglota) e seu download |
| Evento esperado | `.pdf` falso: `DocumentUploaded failure` ("O conteúdo do arquivo não corresponde"). Poliglota: aceito (`success`), download como `attachment` + `nosniff` + `image/png` |
| Observado | 400 e 201; download 200 com `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Content-Type: image/png` (controles OK); `DocumentDownloaded` presente |
| Campos | `outcome`, `properties.details`, `resource` |
| Regras | DR-12 (só o caso rejeitado) |
| Severidade | Medium |
| Detectabilidade | Parcial |
| Lacunas | O poliglota é aceito e não existe sinal de que o conteúdo era suspeito. Proposta: hash SHA-256 do arquivo no evento e varredura de conteúdo (G-P5) |
| Validação | `PT-T13-<RUN>-*`: 1 `DocumentUploaded failure`, 1 `success`, 1 `DocumentDownloaded` |
| Estados | Bloqueada: `failure`. Possível exploração: `success` com tipo incomum. Confirmada: impossível sem inspeção de conteúdo |

## T-14 — Path traversal em nome de arquivo

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/documents/upload` com `filename="../../x.txt"`, `"..\x.txt"` e nome Unicode |
| MITRE | T1190 |
| Comportamento | Nomes com travessia de diretório |
| Evento esperado | `DocumentUploaded success`, `details` com `Arquivo 'x.txt'` **e** `Nome enviado pelo cliente: '../../x.txt'` (novo) |
| Observado | 3× 201, nome gravado `x.txt` (sem diretórios), GUID em disco. O nome Unicode foi corrompido pelo shell do Windows ao enviar (artefato do teste, sem conclusão) |
| Campos | `properties.details` |
| Regras | DR-13 |
| Severidade | Medium |
| Detectabilidade | Total (antes: **Não Detectável**, o nome já chegava sanitizado ao log) |
| Lacunas | Nenhuma conhecida para este vetor |
| Validação | `PT-T14-<RUN>-*`: 3 eventos, 2 com `Nome enviado pelo cliente` contendo `..` ou `\`; DR-13 alerta |
| Estados | Tentativa: `Nome enviado pelo cliente` com `..`. Bloqueada (neutralizada): nome gravado sem diretórios. Exploração: arquivo fora do diretório de upload (não observado; não há evento para isso) |

## T-15 — Limites de tamanho (F-14)

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/documents/upload` |
| MITRE | T1499 Endpoint Denial of Service (aproximada) |
| Comportamento | Arquivo de 5 MiB + 1 e de 10 MiB + 1 |
| Evento esperado | 5 MiB + 1: `DocumentUploaded failure` ("excede o limite de 5 MB"). 10 MiB + 1: apenas `HttpRequest` 400 |
| Observado | Conforme o esperado; `content_length` 5243304 e 10486186 nos `HttpRequest` (campo novo) |
| Campos | `content_length`, `status_code`, `endpoint`, `properties.details` |
| Regras | DR-12, DR-14 |
| Severidade | Low |
| Detectabilidade | Total |
| Lacunas | Resposta é 400 (não 413) e a causa do 400 acima de 10 MiB não é registrada, só se infere por `content_length` |
| Validação | `PT-T15-<RUN>-*`: 1 evento de auditoria (5 MiB) e 2 `HttpRequest` com `content_length` ≥ 5 MiB |
| Estados | Tentativa: `content_length` alto. Bloqueada: 400. Exploração: n/a (nenhum arquivo gravado) |

## T-16 — Injection e XSS refletido em busca

| Campo | Conteúdo |
|---|---|
| Endpoint | `GET /search?q=`, `GET /documents?q=`, `GET /api/documents?q=` |
| MITRE | T1190 |
| Comportamento | 7 payloads (`'`, `" OR 1=1 --`, `<script>…`, `%`, `_`, `' UNION SELECT NULL--`, `../../etc/passwd`) × 3 rotas, como `employee` |
| Evento esperado | `HttpRequest` com `query_string` (codificada), `status_code` 200, sem `ApplicationError` |
| Observado | 21 requisições, todas 200, `query_string` registrada, nenhum `ApplicationError` |
| Campos | `event_type=HttpRequest`, `endpoint`, `query_string`, `status_code`, `username`, `source_ip` |
| Regras | DR-15 |
| Severidade | Medium (High com ≥ 5 acertos em 5 min, indício de ferramenta) |
| Detectabilidade | Parcial |
| Lacunas | O aplicativo trata tudo como texto (200): não há evento que diferencie "bloqueado" de "ignorado"; a regra sinaliza tentativa, não exploração. POST (corpo) não é visível |
| Validação | `PT-T16-<RUN>-*`: 21 `HttpRequest`; DR-15 classifica sqli/xss/traversal/meta_char |
| Estados | Tentativa: `query_string` com padrão. Bloqueada: n/a (200 de texto escapado). Possível exploração: 5xx ou `ApplicationError` após o payload (DR-21). Nenhuma observada |

## T-17 — XSS armazenado

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/documents` (JSON) e `GET /documents/{id}` |
| MITRE | T1190; impacto T1059.007 |
| Comportamento | Criar documento com `<img src=x onerror=alert(1)>` e abrir a página |
| Evento esperado | `DocumentCreated document.create` (benigno por si só) |
| Observado | 201 e `DocumentCreated`; página renderiza `&lt;img` (codificado, controle OK) |
| Campos | — |
| Regras | Nenhuma viável (G-P1) |
| Severidade | — |
| Detectabilidade | Não Detectável |
| Lacunas | O corpo não é registrado e `details` não inclui título/conteúdo: o payload não deixa rastro. Proposta: alerta no próprio portal (evento `SuspiciousInput` com **categoria**, nunca o valor) ou WAF na frente |
| Validação | `PT-T17-<RUN>-*`: só `DocumentCreated` + `DocumentAccessed`. Documentar `NOT SUPPORTED` |
| Estados | Tentativa e bloqueio: invisíveis. Falha de detecção: confirmada |

## T-18 — Open redirect em login

| Campo | Conteúdo |
|---|---|
| Endpoint | `GET /login?returnUrl=…` e `POST /login` com `ReturnUrl` externo |
| MITRE | T1566.002 Spearphishing Link (aproximada, uso posterior) |
| Comportamento | `https://evil.test/phish` e `//evil.test/phish` |
| Evento esperado | GET: `HttpRequest` com `query_string=returnUrl=…`. POST com credenciais válidas: `UserLogin` + `AccessDenied login.external_return_url_blocked` (novo), 302 → `/dashboard` |
| Observado | Conforme o esperado nos dois formatos |
| Campos | `query_string`, `event_type`, `action`, `resource`, `username` |
| Regras | DR-17 |
| Severidade | Medium |
| Detectabilidade | Total (antes: Parcial, o `ReturnUrl` do POST é corpo) |
| Lacunas | Só dispara com login **bem-sucedido** (o redirecionamento só ocorre aí); tentativas com credencial inválida só aparecem no GET |
| Validação | `PT-T18-<RUN>-*`: 1 `HttpRequest` com `returnUrl` e 2 `AccessDenied login.external_return_url_blocked` |
| Estados | Tentativa: `returnUrl` externo no GET/evento. Bloqueada: evento + 302 `/dashboard`. Exploração: 302 com `Location` externo (não ocorre) |

## T-19 — Enumeração no cadastro (F-07)

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/auth/register` |
| MITRE | T1087 Account Discovery; T1589.002 |
| Comportamento | Usuário existente e e-mail existente |
| Evento esperado | `UserCreated user.self_registered` `outcome=failure`, `details="Cadastro rejeitado: DuplicateUserName"` / `DuplicateEmail` |
| Observado | 400 e os dois eventos |
| Campos | `event_type`, `outcome`, `username`, `source_ip`, `properties.details` |
| Regras | DR-18 |
| Severidade | Low (Medium com ≥ 3 falhas por IP) |
| Detectabilidade | Total |
| Lacunas | O e-mail tentado não é registrado (apenas o usuário) |
| Validação | `PT-T19-<RUN>-*`: 2 eventos com os códigos |
| Estados | Tentativa e bloqueio: `UserCreated failure`. Exploração: o próprio texto da resposta revela existência (F-07), sem evento adicional |

## T-20 — Mass assignment no cadastro

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/auth/register` com `"role":"ADMIN","isAdmin":true` |
| MITRE | T1136 Create Account; T1068 (tentativa) |
| Comportamento | Conta nova com campos de papel no JSON |
| Evento esperado | `UserCreated success`, `details="…papel GUEST."` |
| Observado | 201, papel retornado `GUEST` |
| Campos | `event_type`, `outcome`, `properties.details` |
| Regras | DR-18 |
| Severidade | Low |
| Detectabilidade | Parcial |
| Lacunas | O envio de `role`/`isAdmin` é invisível (corpo não registrado), igual a T-05 |
| Validação | `PT-T20-<RUN>-001`: `UserCreated success` com "GUEST" |
| Estados | Tentativa: invisível. Bloqueada (neutralizada): `details` com GUEST. Exploração: `UserCreated` com papel ≠ GUEST (nenhuma) |

## T-21 — Enumeração por tempo (F-11)

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/auth/login` (4 com usuário existente, 4 inexistentes) |
| MITRE | T1087 (aproximada) |
| Comportamento | Medir o tempo de resposta para usuário existente vs inexistente. Amostra pequena de propósito, abaixo do lockout; **não é análise estatística** |
| Evento esperado | `UserLoginFailed` com `details` = `Senha inválida.` ou `Usuário inexistente.`; `HttpRequest` com `duration_ms` |
| Observado | Mediana de `duration_ms` ≈ 55 ms (existente) vs ≈ 7 ms (inexistente; 1ª chamada fria 63 ms). Indício de F-11, ainda **potencial** |
| Campos | `properties.details`, `duration_ms`, `username`, `source_ip` |
| Regras | DR-04 (enumeração por usuário inexistente) |
| Severidade | Low |
| Detectabilidade | Parcial |
| Lacunas | Nenhuma regra alerta o canal de tempo em si; só o volume de tentativas com usuário inexistente |
| Validação | `PT-T21-<RUN>-*`: 4 + 4 eventos com `details` distintos |
| Estados | Tentativa: padrão de falhas com `Usuário inexistente.`. Bloqueada: n/a. Exploração: não observável por log |

## T-22 — Tratamento de erros (F-12)

| Campo | Conteúdo |
|---|---|
| Endpoint | `/error/0`, `/error/5000`, `/error/abc`, `/error/404`, `/error/403` (anônimo) |
| MITRE | Sem correspondência direta |
| Comportamento | Status fora do intervalo e valor não numérico |
| Evento esperado | `HttpRequest`; `ApplicationError` se houver exceção |
| Observado | `/error/0`: **conexão encerrada sem resposta**, log `status_code=0`. `/error/5000`: cliente recebe 500, log `status_code=5000` (severity high). `/error/abc`: 302 para login. Sem stack trace no corpo e **sem `ApplicationError`** |
| Campos | `status_code`, `severity`, `endpoint`, `source_ip` |
| Regras | DR-21 |
| Severidade | Low |
| Detectabilidade | Parcial |
| Lacunas | O `status_code` do log pode divergir do que o cliente vê; nenhuma exceção é registrada para o `/error/0`. Correção funcional (limitar o intervalo em `ErrorController`) fica a critério do dono do código |
| Validação | `PT-T22-<RUN>-*`: `HttpRequest` com `status_code` 0 e 5000 |
| Estados | Tentativa: `/error/<n>` com n fora de 100–599. Exploração: não há |

## T-23 — Cabeçalhos / misconfiguration

| Campo | Conteúdo |
|---|---|
| Endpoint | `/login` (anônimo) e `/dashboard` (autenticado) |
| MITRE | T1595.002 Vulnerability Scanning (reconhecimento) |
| Comportamento | Inspecionar cabeçalhos de resposta |
| Evento esperado | Nenhum além do `HttpRequest` 200 |
| Observado | Presentes: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, COOP, Cache-Control. Ausente: HSTS (F-05) |
| Campos | — |
| Regras | Nenhuma |
| Severidade | — |
| Detectabilidade | Não Detectável |
| Lacunas | Teste passivo: cabeçalhos de resposta não são logados e uma leitura legítima é idêntica à de um scanner. Cobertura correta: verificação sintética periódica, não SIEM |
| Validação | n/a |
| Estados | Todos "sem telemetria" por natureza do teste |

## T-24 — Consistência 401 / 403 / 404

| Campo | Conteúdo |
|---|---|
| Endpoint | `/api/foo`, `/api/documents`, `/api/admin/users`, `/rota-inexistente`, com e sem cookie |
| MITRE | T1595.003 Wordlist Scanning (aproximada) |
| Comportamento | Comparar respostas para rotas autenticadas, negadas e inexistentes |
| Evento esperado | 401: `AuthenticationRequired authentication.challenge` (category `security`). 403: `AccessDenied policy_denied`. 404: só `HttpRequest` |
| Observado | Anônimo: `/api/foo` 401, `/api/documents` 401, `/rota-inexistente` 302 (login). `employee`: `/api/foo` 404, `/rota-inexistente` 404. `guest` em `/api/admin/users`: 403 |
| Campos | `event_type`, `endpoint`, `status_code`, `source_ip` |
| Regras | DR-10, DR-22 (rajadas de 401 e de 404) |
| Severidade | Low |
| Detectabilidade | Total |
| Lacunas | Rota API inexistente devolve 401 para anônimo e 404 para autenticado (comportamento observado do fallback policy), o que ajuda a distinguir sessões válidas |
| Validação | `PT-T24-<RUN>-*`: 1 `AuthenticationRequired` em `/api/documents` (e em `/api/foo`), 1 `AccessDenied` |
| Estados | Tentativa: 401/404 em sequência por IP. Bloqueada: 401/403. Exploração: 200 em rota protegida sem cookie (nenhuma) |

## T-25 — `X-Request-ID` forjado

| Campo | Conteúdo |
|---|---|
| Endpoint | `GET /login` com `X-Request-ID` válido e inválido |
| MITRE | T1070 Indicator Removal (aproximada: adulteração de log) |
| Comportamento | ID válido reaproveitado; ID com espaço e `;` substituído |
| Evento esperado | ID válido: `request_id` igual ao enviado. Inválido: GUID novo no cabeçalho e no log, `properties.request_id_rejected` com o valor enviado (limpo, ≤ 64) |
| Observado | Conforme o esperado. CR/LF não testado (curl impede); coberto pelo regex `^[A-Za-z0-9._-]{8,64}$` e pelos testes xUnit |
| Campos | `request_id`, `properties.request_id_rejected` |
| Regras | DR-20 |
| Severidade | Low |
| Detectabilidade | Total (antes: Não Detectável, o valor rejeitado se perdia) |
| Lacunas | ID válido forjado (colidir com o de outra requisição) continua aceito por design (F-13) |
| Validação | `PT-T25-<RUN>-*`: 1 `HttpRequest` com `request_id_rejected` |
| Estados | Tentativa e bloqueio: `request_id_rejected`. Exploração: IDs duplicados com `source_ip` distintos (DR-20 opcional) |

## T-26 — Dado sensível em `username` (F-09)

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /api/auth/login` com `userName` `senha123` e `P@ssw0rd!2026` |
| MITRE | T1552 Unsecured Credentials (aproximada: exposição em log) |
| Comportamento | Digitar a senha no campo de usuário |
| Evento esperado | `UserLoginFailed`, `username` com o texto, `details="Usuário inexistente."` |
| Observado | **F-09 confirmado**: o texto fica em claro em `username` (log e `audit_events`) |
| Campos | `username`, `properties.details` |
| Regras | DR-19 (usernames fora do padrão `[A-Za-z0-9._-]`) |
| Severidade | Medium |
| Detectabilidade | Parcial |
| Lacunas | `senha123` é um username válido sintaticamente: DR-19 só pega senhas com símbolo. A correção real é mascarar na origem (G-P4) |
| Validação | `PT-T26-<RUN>-*`: 2 eventos; DR-19 alerta o segundo |
| Estados | Tentativa e vazamento: o próprio evento. Exploração: leitura do log por terceiro, fora do alcance do SIEM |

## T-27 — Auditoria da auditoria

| Campo | Conteúdo |
|---|---|
| Endpoint | `GET /api/admin/logs`, `GET /admin/logs` como `admin` |
| MITRE | T1654 Log Enumeration |
| Comportamento | Consultar a trilha de auditoria |
| Evento esperado | `AdminAction audit_log.viewed` (Low) |
| Observado | 2 eventos |
| Campos | `event_type`, `action`, `username`, `source_ip` |
| Regras | DR-23 (visibilidade) |
| Severidade | Info/Low |
| Detectabilidade | Total |
| Lacunas | O filtro usado na consulta (`eventType`, `pageSize`) não é registrado |
| Validação | `PT-T27-<RUN>-*`: 2 `AdminAction` |
| Estados | Evento = exploração legítima por admin; anomalia só por baseline (outro IP/horário) |

## T-28 — Unlock por não-admin (F-10)

| Campo | Conteúdo |
|---|---|
| Endpoint | `POST /admin/users/{id}/unlock` como `employee` |
| MITRE | T1190 (aproximada: BFLA) |
| Comportamento | Chamar a ação de admin sem token antiforgery |
| Evento esperado | `AccessDenied authorization.policy_denied` (`resource=/admin/users/N/unlock`) |
| Observado | 302 → `/access-denied`; evento presente; nenhum `AdminAction`. F-10 **refutado em parte**: a policy audita a negação antes do service |
| Campos | `event_type`, `action`, `resource`, `username` |
| Regras | DR-10 |
| Severidade | Medium |
| Detectabilidade | Total |
| Lacunas | O evento específico `user.unlock_denied` do `UserService` continua inalcançável via HTTP (código morto defensivo) |
| Validação | `PT-T28-<RUN>-001`: 1 `AccessDenied`, 0 `AdminAction` |
| Estados | Tentativa e bloqueio: `AccessDenied`. Exploração: `AdminAction user.unlocked` por ator não-admin (nenhuma) |
