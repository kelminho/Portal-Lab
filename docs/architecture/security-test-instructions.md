# Instruções para os testes de segurança — SecureCorpPortal

> Documento operacional para quem executará os testes de segurança no laboratório.
> Baseado na revisão técnica do repositório (commit `5f071a3`). Evidências citam arquivo e linha.
> **Uso exclusivo em ambiente local/isolado e autorizado.**

## Sumário

1. [Regras e escopo](#1-regras-e-escopo)
2. [Pré-requisito bloqueante](#2-pré-requisito-bloqueante)
3. [Preparação do ambiente](#3-preparação-do-ambiente)
4. [Contas e papéis](#4-contas-e-papéis)
5. [Superfície de ataque](#5-superfície-de-ataque)
6. [Achados conhecidos](#6-achados-conhecidos)
7. [Matriz de testes manuais](#7-matriz-de-testes-manuais)
8. [Uso das ferramentas](#8-uso-das-ferramentas)
9. [Como coletar evidências nos logs](#9-como-coletar-evidências-nos-logs)
10. [Testes automatizados](#10-testes-automatizados)
11. [Estrutura futura do Lab/](#11-estrutura-futura-do-lab)
12. [Critérios de aceite e registro de resultados](#12-critérios-de-aceite-e-registro-de-resultados)

---

## 1. Regras e escopo

**Permitido**
- Alvo único: `http://127.0.0.1:8080` (Docker) ou `http://localhost:5080` (`dotnet run`).
- Somente as contas de demonstração da seção 4 (dados fictícios).
- Testes não destrutivos, com taxa limitada (ver seção 8).

**Proibido**
- Qualquer alvo externo ou rede que não seja o laboratório.
- Credenciais ou dados reais.
- Desabilitar controles de segurança para "fazer o teste passar".
- Varreduras agressivas automáticas antes de mapear endpoints.
- Alterar o código principal. Vulnerabilidades intencionais só entram via módulos em `Lab/`, com autorização posterior.

**Classificação dos resultados**
- **Confirmado**: reproduzido, com evidência (requisição/resposta + log).
- **Potencial**: hipótese que depende de validação dinâmica.
- **Controle OK**: comportamento seguro observado.

Não classifique algo como confirmado sem evidência.

## 2. Pré-requisito bloqueante

O diretório `src/SecureCorpPortal/Data/` **não está no Git**: `.gitignore:26-27` (`data/`) o exclui por causa de `core.ignorecase=true` no Windows. Um clone limpo falha com `CS0234: namespace 'Data' não existe`.

Antes de testar a partir de um clone:

1. Trocar as regras por `/data/` (ancorada) e executar `git add src/SecureCorpPortal/Data`.
2. Validar: `git check-ignore -v src/SecureCorpPortal/Data/AppDbContext.cs` não deve retornar nada.
3. Clonar em pasta nova e executar `docker compose up -d --build`.

Enquanto isso não for feito, teste apenas a cópia de trabalho local.

## 3. Preparação do ambiente

```bash
cp .env.example .env                    # opcional
docker compose up -d --build            # app em 127.0.0.1:8080, PostgreSQL só na rede interna
curl -s http://127.0.0.1:8080/health    # deve responder Healthy
```

- Logs em `./logs/`: `securecorp-AAAAMMDD.json` (tudo) e `security-AAAAMMDD.json` (somente `audit` e `security`).
- Reset do estado: `docker compose down -v` (apaga banco e uploads) e `up -d` novamente.
- Desenvolvimento: `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d db` e `dotnet run --project src/SecureCorpPortal`.
- Mantenha `ASPNETCORE_ENVIRONMENT=Production`. Em `Development` o `DeveloperExceptionPage` pode expor stack traces.

Login por API e reutilização do cookie:

```bash
curl -c jar.txt -H "Content-Type: application/json" \
  -d '{"userName":"employee","password":"Employee@123!"}' \
  http://127.0.0.1:8080/api/auth/login
curl -b jar.txt http://127.0.0.1:8080/api/auth/me
```

## 4. Contas e papéis

Fictícias, definidas em `Data/DemoAccounts.cs` e no `README.md`.

| Usuário | Senha | Papel | Lê até | Cria até |
|---|---|---|---|---|
| `admin` | `Admin@123!` | ADMIN | Restricted | Restricted |
| `analyst` | `Analyst@123!` | ANALYST | Confidential | Confidential |
| `employee` | `Employee@123!` | EMPLOYEE | Internal | Internal |
| `guest` | `Guest@123!` | GUEST | Public | não cria |
| `marcos.oliveira`, `patricia.santos` | `Employee@123!` | EMPLOYEE | Internal | Internal |

O dono sempre lê o próprio documento. Só ADMIN exclui documentos e usuários. Lockout: 5 falhas, 15 minutos.

## 5. Superfície de ataque

**Anônimo**: `/`, `/login`, `/register`, `/access-denied`, `/health`, `/error`, `/error/{n}`, `POST /api/auth/login`, `POST /api/auth/register`, arquivos estáticos.

**Autenticado (qualquer papel)**: `/dashboard`, `/documents` (lista, detalhe, download), `/search`, `/profile`, `/api/dashboard`, `/api/documents*`, `/api/users/{id}` (próprio), `/api/auth/me|logout`.

**Com policy**:

| Policy | Papéis | Endpoints |
|---|---|---|
| `CanViewUserDirectory` | ADMIN, ANALYST | `/users`, `/users/{id}`, `GET /api/users` |
| `CanCreateDocuments` | ADMIN, ANALYST, EMPLOYEE | `/documents/upload`, `POST /api/documents`, `POST /api/documents/upload` |
| `AdminOnly` | ADMIN | `/admin/*`, `/api/admin/*`, exclusão de documentos e usuários |

**Controles verificados no código**: fallback policy (`Policies.cs:36`), `[AutoValidateAntiforgeryToken]` no MVC (`PortalControllerBase.cs:11`), `DocumentAccessPolicy`, DTOs explícitos, upload com allowlist + magic bytes + GUID + fora de `wwwroot` (`LocalFileStorageService.cs`), CSP sem inline, EF Core só com LINQ.

**Sem superfície hoje**: SSRF, command injection, SQL manual, `Html.Raw`, CORS (não configurado, portanto nega), recuperação de senha, MFA.

## 6. Achados conhecidos

Os testes da seção 7 devem confirmar ou refutar cada um. `[C]` = confirmado no código, `[P]` = potencial.

| ID | Tipo | Sev. | Resumo | Evidência |
|---|---|---|---|---|
| F-01 | C | Crítica | `Data/` ignorado pelo Git; clone não compila | `.gitignore:26-27` |
| F-02 | C | Média | Sem rate limiting; lockout só por conta (spraying e DoS de conta) | `Program.cs:62-74`; `ServiceCollectionExtensions.cs:58-59` |
| F-03 | C | Média | Logout não invalida a sessão no servidor (sem `UpdateSecurityStampAsync`); cookie vale até 30 min | `AuthService.cs:170-185` |
| F-04 | C | Baixa/Média | API sem antiforgery (`upload` multipart, `logout`); depende só de `SameSite=Strict` | `DocumentsApiController.cs:73-85`; `AuthApiController.cs:57-63` |
| F-05 | C | Baixa (lab) | `SecurePolicy.SameAsRequest`, sem HTTPS/HSTS, antiforgery sem `Secure` | `ServiceCollectionExtensions.cs:80,90-95` |
| F-06 | C | Média (mitigada) | Seed ligado por padrão no Docker com credenciais públicas, sem trava por ambiente | `docker-compose.yml:46`; `DatabaseInitializer.cs:39-43` |
| F-07 | C | Baixa | Cadastro revela usuário/e-mail já existentes | `PortugueseIdentityErrorDescriber.cs:20-24` |
| F-08 | C | Baixa | Documento: 404 (inexistente) vs 403 (sem permissão); IDs sequenciais | `DocumentService.cs:55-65,157-167` |
| F-09 | C | Baixa | Username de login falho vai para log/auditoria; senha digitada no campo errado é registrada | `AuthService.cs:70,77`; `AuditService.cs:53` |
| F-10 | C | Baixa | Sem auditoria: negação de `unlock`, leitura do diretório de usuários, falha de antiforgery, 404 repetidos | `UserService.cs:249-254,85-101` |
| F-11 | P | Baixa | Enumeração por tempo no login (usuário inexistente/inativo não calcula hash) | `AuthService.cs:73-92` |
| F-12 | P | Baixa | `/error/{n}` anônimo aceita qualquer inteiro | `ErrorController.cs:23-33` |
| F-13 | P | Info | Sem `Cache-Control: no-store` (não localizado); `AllowedHosts: "*"`; `X-Request-ID` forjável | `SecurityHeadersMiddleware.cs`; `appsettings.json:38`; `CorrelationMiddleware.cs:28` |
| F-14 | P | Baixa | Upload sem cota; `.docx`/`.xlsx` validados só por assinatura ZIP; arquivo órfão se o banco falhar | `LocalFileStorageService.cs:41-49`; `DocumentService.cs:128-143` |
| F-15 | P | Info | Docker sem `HEALTHCHECK`/`read_only`/`cap_drop`; senha padrão do Postgres | `Dockerfile`; `docker-compose.yml:22` |
| F-16 | Doc | Média | Oito documentos referenciados não existem; sem `LICENSE`/`SECURITY.md` | `README.md:428-435` |
| F-17 | C | Info | Sem recuperação de conta, MFA, confirmação de e-mail, expiração absoluta de sessão | `ServiceCollectionExtensions.cs:63,81-82` |

Documentos ausentes: `docs/security/{permissions, security-baseline, extension-points, exercise-template}.md` e `docs/siem/{log-schema, event-catalog, detection-use-cases, integration-guide}.md`.

## 7. Matriz de testes manuais

Use `jar.txt` por usuário (`jar-employee.txt` etc.). Registre `X-Request-ID` de cada resposta.

| ID | Endpoint / função | Classe | Pré-requisito / papel | Procedimento | Comportamento seguro esperado | Evidência no log |
|---|---|---|---|---|---|---|
| T-01 | `GET /api/documents/{id}` (IDs 1–15) | IDOR / enumeração (F-08) | employee | Varrer IDs; comparar 200, 403, 404 | 403 para Confidential/Restricted de terceiros; 404 só para inexistentes | `AccessDenied` `document.read_denied` (Medium); mesmo `request_id` no `HttpRequest` |
| T-02 | `GET /documents/{id}/download` | IDOR em arquivo | employee, guest | Baixar documento acima da classificação | 403, sem corpo do arquivo | `AccessDenied` `document.download_denied` |
| T-03 | `GET /api/users/{id}` | IDOR em usuários | employee | Pedir o ID de outro usuário e IDs inexistentes | 403 em ambos (autorização antes da busca) | `AccessDenied` `user.read_denied` |
| T-04 | `PUT /api/users/{id}` com `{"role":"ADMIN"}` | Escalonamento vertical | employee | Enviar com o próprio ID e o de outro | 403 | `AccessDenied` `user.privilege_change_denied` (High) |
| T-05 | `PUT /api/users/{id}` com `isActive`, campos extras | Mass assignment | employee | Enviar propriedades não previstas | Propriedades ignoradas ou 403; estado inalterado | `UserUpdated` só com campos permitidos |
| T-06 | `/admin/*`, `/api/admin/*`, `/users`, `/documents/upload` | BFLA / matriz de papéis | todos os papéis | Acessar cada rota com cada papel | Conforme a seção 5 | `AccessDenied` `authorization.policy_denied` |
| T-07 | `POST /api/auth/login` (6 falhas) | Força bruta / lockout | conta de seed | 5 senhas erradas, depois a correta | Bloqueio na 5ª; senha correta negada durante o bloqueio | `UserLoginFailed` x5, `UserLockedOut` (High) |
| T-08 | `POST /api/auth/login` vários usuários, 1 senha | Spraying (F-02) | anônimo | Uma senha contra todas as contas de seed | Esperado seguro: throttling por IP. Hoje: sem bloqueio | Sequência `UserLoginFailed` do mesmo `source_ip` |
| T-09 | `POST /api/auth/logout` + reuso do cookie | Sessão (F-03) | employee | Guardar cookie, logout, reenviar em `/api/auth/me` | Seguro: 401. Hoje: provável 200 | `UserLogout` seguido de requisição autenticada |
| T-10 | `POST /login` sem token | CSRF MVC | anônimo | `curl -d` sem antiforgery | 400 | `HttpRequest` com `status_code` 400 |
| T-11 | `POST /api/documents/upload` por formulário de outra porta de `localhost` | CSRF API (F-04) | employee logado | Página HTML local em outra porta com `<form enctype=multipart>` | Seguro: rejeitado. Hoje: depende de ser same-site | `DocumentUploaded` originado sem a UI |
| T-12 | `POST /api/documents/upload` | Upload: tipo | employee | `.exe`, `.html`, `.svg`, `.docm`; arquivo com `MZ` | 400 | `DocumentUploaded` `success=false` |
| T-13 | idem | Upload: conteúdo | employee | `.pdf` sem `%PDF`; `.png` com cabeçalho válido seguido de HTML | Sem assinatura: 400. Com assinatura: aceito, baixado como `attachment` + `nosniff` | `DocumentUploaded` |
| T-14 | idem | Path traversal | employee | `filename="../../x.txt"`, `..\\x.txt`, nome Unicode | Só o nome base; GUID em disco; fora de `wwwroot` | `Details` sem diretórios |
| T-15 | idem | Limites (F-14) | employee | Arquivo de 5 MB + 1 byte; 10 MB + 1 | 400 / 413 | Evento de rejeição com tamanho |
| T-16 | `GET /search?q=` e `/documents?q=` | Injection / XSS | employee, analyst | `'`, `" OR 1=1`, `<script>`, `%`, `_` | Tratado como texto; sem erro 500; HTML codificado | Sem `ApplicationError` |
| T-17 | `POST /api/documents` (título e conteúdo) | XSS armazenado | employee | Criar com `<img src=x onerror=...>`; abrir em `/documents/{id}` | Renderizado codificado; CSP bloqueia inline | — |
| T-18 | `POST /login` com `returnUrl` externo | Open redirect | anônimo | `returnUrl=https://evil.test` e `//evil.test` | Vai para `/dashboard` | — |
| T-19 | `POST /api/auth/register` | Enumeração (F-07) | anônimo | Repetir usuário e e-mail existentes | Hoje revela; registrar como achado | `UserCreated` `success=false` |
| T-20 | `POST /api/auth/register` com `role` no JSON | Mass assignment | anônimo | Enviar `"role":"ADMIN"` | Conta criada como GUEST | `UserCreated` com `GUEST` |
| T-21 | 30 logins com usuário existente x 30 inexistente | Tempo (F-11) | anônimo | Comparar medianas | Diferença estatisticamente nula | `Details` distintos por tipo |
| T-22 | `/error/0`, `/error/5000`, `/error/abc` | Tratamento de erros (F-12) | anônimo | Observar status e corpo | Resposta controlada, sem stack trace | `ApplicationError` se houver exceção |
| T-23 | Cabeçalhos de qualquer página | Misconfiguration | anônimo e logado | Conferir CSP, XFO, nosniff, Referrer-Policy, COOP; ausência de `Cache-Control`/HSTS (F-05, F-13) | Headers presentes; lacunas registradas | — |
| T-24 | `GET /api/foo`, rota inexistente, com e sem cookie | Consistência 401/403/404 | anônimo e logado | Comparar respostas | JSON `ProblemDetails` com `request_id` | `HttpRequest` com o status |
| T-25 | `X-Request-ID` forjado | Integridade dos logs (F-13) | qualquer | Enviar IDs válidos e inválidos (CR/LF) | Inválido substituído; válido reutilizado | `request_id` do log |
| T-26 | Username `senha123` no login | Dados sensíveis (F-09) | anônimo | Falha de login com valor que imita senha | Idealmente mascarado. Hoje fica em log | `UserLoginFailed` com `username` |
| T-27 | `/admin/logs`, `/api/admin/logs` | Auditoria da auditoria | admin | Consultar e verificar o evento | Evento registrado | `AdminAction` `audit_log.viewed` |
| T-28 | Unlock por não-admin | Auditoria de negação (F-10) | employee | `POST /admin/users/{id}/unlock` | 403 | Hoje sem `AccessDenied` específico |

## 8. Uso das ferramentas

Todas apenas contra `127.0.0.1`, **após** ter o mapa da seção 5.

- **Burp Suite / ZAP**: proxy em `127.0.0.1:8080`; sessão autenticada por cookie (`SecureCorp.Auth`); escopo restrito ao host; modo manual e *spider* leve. Active scan somente depois de T-01 a T-28, com limite de threads baixo.
- **curl / Postman**: coleção com um ambiente por papel (cookie por usuário). Exportar a coleção para `docs/`.
- **ffuf / Gobuster**: foco em IDs (`/api/documents/FUZZ`, `/documents/FUZZ/download`, `/api/users/FUZZ`) e diretórios. Wordlists curtas, `-rate 5` ou equivalente, autenticado.
- **Nuclei**: templates de misconfiguration e exposição (headers, painéis, arquivos comuns). Sem templates de DoS ou brute force.

Observação: sem rate limiting (F-02), varreduras geram muito ruído em `audit_events` e nos logs. Faça `docker compose down -v` entre rodadas se quiser uma linha de base limpa.

## 9. Como coletar evidências nos logs

Campos relevantes (JSON Lines): `timestamp`, `severity`, `event_type`, `event_category`, `action`, `request_id`, `source_ip`, `user_id`, `username`, `http_method`, `endpoint`, `status_code`, `resource`, `properties.details`.

```bash
# Tudo de uma requisição (use o X-Request-ID da resposta)
grep '"request_id":"<ID>"' logs/securecorp-*.json

# Somente auditoria e segurança
grep '"event_type":"AccessDenied"' logs/security-*.json
grep '"event_type":"UserLoginFailed"' logs/security-*.json

# Via API (admin)
curl -b jar-admin.txt "http://127.0.0.1:8080/api/admin/logs?eventType=AccessDenied&pageSize=50"
```

Cada resultado deve ter: requisição (comando), resposta (status e trecho), `request_id` e o evento correspondente no log, ou a ausência dele quando for lacuna de auditoria.

Limitações para análise de SIEM: formato JSON próprio (sem ECS/CEF), sem proteção de integridade dos arquivos, `audit_events` editável pela aplicação, `source_ip` sem `ForwardedHeaders` atrás de proxy.

## 10. Testes automatizados

**Estado**: 94 métodos / 188 casos (xUnit, `WebApplicationFactory`, EF InMemory) em `tests/SecureCorpPortal.Tests`.

**Execução**: exige o runtime **.NET 8**. Na máquina da revisão só havia .NET 10; com `DOTNET_ROLL_FORWARD=Major` houve 74 passes e 114 falhas por `PipeWriter ... does not implement UnflushedBytes` (incompatibilidade do TestServer 8 com o framework 10, **não** defeito da aplicação). Resultado inconclusivo até rodar em ambiente correto:

```bash
docker compose --profile test run --rm tests
```

**Testes a acrescentar**

| Área | Teste ausente |
|---|---|
| Autorização | IDOR por ID sequencial em `/api/documents/{id}` e `/api/users/{id}`; dono com classificação acima do papel; classificação numérica inválida no JSON |
| CSRF | API (`upload`, `logout`) e ações MVC de admin; hoje só o login é coberto |
| Sessão | Reuso de cookie após logout (F-03); revalidação após mudança de papel |
| Upload | ZIP poliglota; extensão dupla; nome com Unicode ou ponto final; cota |
| Auditoria | Negação de `unlock`; leitura do diretório; falha de antiforgery; username parecido com senha (F-09) |
| Erros | `/error/{n}` fora do intervalo (F-12) |
| Rate limiting | Após implementar |
| Lab | Com `SecurityLab:Enabled=true` e nenhum módulo, nenhuma rota `/lab/*`; recusa em `Production` |

**InMemory vs PostgreSQL (efeito em segurança)**: o InMemory não impõe índices únicos nem foreign keys (corrida de cadastro e `ON DELETE SET NULL` não exercitados), ignora limites de coluna, não exige `DateTimeKind.Utc` e difere em collation/tradução de `ToLower().Contains`. Recomendado: pequena suíte de integração com PostgreSQL real (Testcontainers ou o `db` do compose).

## 11. Estrutura futura do Lab/

Hoje `Lab/` contém só o contrato (`ILabModule`) e `AvailableModules = []` (`SecurityLabExtensions.cs:43`). Nenhum cenário vulnerável existe, e **nada deve ser introduzido nos controllers/services principais**.

**Desenho proposto** (depende de autorização posterior):
- Módulo em `Lab/Modules/<Id>/`, rotas `/lab/<id>/vulnerable/...` e `/lab/<id>/secure/...`.
- Dupla ativação (`SecurityLab:Enabled` + id em `EnabledModules`) e **recusa de subir em `Production`** (falta hoje).
- Schema/tabelas próprios (`lab_*`) com dados fictícios; contas dedicadas (`lab.alice`, `lab.bob`); policy `LabParticipant`.
- `POST /lab/_reset` (ADMIN) para restaurar o estado inicial.
- Auditoria com campos `lab_module` e `variant`, para comparar o comportamento seguro e o vulnerável nos logs.

| Prioridade | Módulo | Complexidade |
|---|---|---|
| 1 | LAB-01 IDOR/BOLA em documentos | Baixa |
| 1 | LAB-02 Mass assignment em perfil | Baixa |
| 1 | LAB-03 Força bruta / spraying | Baixa |
| 2 | LAB-04 XSS refletido e armazenado | Média |
| 2 | LAB-05 Upload inseguro | Média |
| 2 | LAB-06 SQL injection | Média |
| 3 | LAB-07 CSRF na API | Média |
| 3 | LAB-08 Sessão após logout | Média |
| 3 | LAB-09 SSRF | Alta |
| 3 | LAB-10 Path traversal | Alta |

## 12. Critérios de aceite e registro de resultados

**Ordem de correção sugerida**: F-01, F-16, F-06, F-03, F-02, F-04, F-10, F-09; depois testes e `Lab/`.

**Veredito vigente**: **NOT READY** para publicação (F-01 impede o build após clonar). Corrigidos F-01 e F-16, passa a **READY WITH RESTRICTIONS**:
- uso somente em `127.0.0.1` ou rede isolada;
- sem rate limit, HTTPS ou HSTS;
- sessão não invalidada no logout;
- API sem antiforgery;
- seed público ligado por padrão;
- sem módulos de laboratório;
- suíte de testes ainda não confirmada em ambiente com .NET 8.

**Modelo de registro** (um por teste executado):

```text
ID do teste:        T-xx
Data/hora (UTC):
Executor:
Papel/usuário:
Comando/requisição:
Resposta (status + trecho):
X-Request-ID:
Evento(s) no log:
Resultado:          Controle OK | Confirmado | Potencial | Não reproduzido
Achado relacionado: F-xx
Observações:
```
