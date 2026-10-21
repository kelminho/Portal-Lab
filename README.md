# SecureCorp Portal

Portal corporativo **fictício** construído em C#/.NET 8 para estudo de ASP.NET Core e para servir,
futuramente, como **fonte de eventos em um laboratório isolado de SOC/SIEM**.

> ⚠️ **Uso exclusivamente laboratorial.** A empresa, os usuários e os documentos são fictícios.
> As credenciais de demonstração são públicas. Não publique, não hospede e não exponha esta
> aplicação à internet. O `docker-compose.yml` publica a porta apenas em `127.0.0.1`.

---

## Sumário

1. [Objetivo](#1-objetivo)
2. [Arquitetura](#2-arquitetura)
3. [Tecnologias](#3-tecnologias)
4. [Estrutura do projeto](#4-estrutura-do-projeto)
5. [Requisitos](#5-requisitos)
6. [Instalação e execução](#6-instalação-e-execução)
7. [Docker](#7-docker)
8. [Banco de dados](#8-banco-de-dados)
9. [Usuários de teste](#9-usuários-de-teste)
10. [Permissões](#10-permissões)
11. [Páginas](#11-páginas)
12. [API REST](#12-api-rest)
13. [Logs](#13-logs)
14. [Auditoria](#14-auditoria)
15. [Testes](#15-testes)
16. [Futuro laboratório de segurança](#16-futuro-laboratório-de-segurança)
17. [Documentação complementar](#17-documentação-complementar)

---

## 1. Objetivo

- Ser uma aplicação **pequena, completa e didática** para aprender C#, ASP.NET Core MVC, EF Core e Identity.
- Simular um sistema interno real: login, cadastro, dashboard, perfil, usuários, documentos, busca,
  upload, área administrativa, API REST, RBAC, auditoria e logging.
- Produzir **logs estruturados em JSON** prontos para serem ingeridos por um SIEM.
- Deixar **pontos de extensão claros** para exercícios de segurança futuros (não implementados nesta etapa).

## 2. Arquitetura

Monólito em camadas: um único projeto web atende as páginas Razor e a API REST.

```
 Navegador / cliente HTTP
          │
          ▼
 ┌──────────────────────── Pipeline ASP.NET Core ─────────────────────────┐
 │ Correlation → ExceptionHandler → StatusCodePages → SecurityHeaders →   │
 │ StaticFiles → Routing → Authentication → RequestLogging → Authorization│
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    ▼
        Controllers MVC (Views Razor)      Controllers API (/api/*, JSON)
                         └────────────┬────────────┘
                                      ▼
                     Services (regras de negócio e autorização)
                 AuthService · UserService · DocumentService · AuditService
                 DashboardService · LocalFileStorageService · DocumentAccessPolicy
                                      ▼
            Repositories / UserManager (Identity)      Disco (uploads)
                                      ▼
                       EF Core (AppDbContext) → PostgreSQL
                                      │
              Serilog (JSON) ─────────┴──────► logs/securecorp-*.json
                                               logs/security-*.json
```

Fluxo detalhado de uma requisição: [docs/architecture/request-flow.md](docs/architecture/request-flow.md).
Decisões de arquitetura: [docs/architecture/overview.md](docs/architecture/overview.md).

## 3. Tecnologias

| Camada | Tecnologia |
|---|---|
| Linguagem / runtime | C# 12, .NET 8 (LTS) |
| Web | ASP.NET Core MVC (Razor Views) + Web API no mesmo projeto |
| Autenticação | ASP.NET Core Identity (cookie, hash de senha, lockout) |
| Autorização | Papéis + policies + regras por recurso (`DocumentAccessPolicy`) |
| Dados | Entity Framework Core 8 + Npgsql (PostgreSQL 16) |
| Logging | Serilog com formatter JSON próprio (`SiemJsonFormatter`) |
| Frontend | Razor, HTML, CSS e JavaScript puro (sem frameworks) |
| Testes | xUnit, `WebApplicationFactory`, EF Core InMemory |
| Infra | Docker, Docker Compose |

## 4. Estrutura do projeto

```
SecureCorpPortal/
├── SecureCorpPortal.sln
├── src/SecureCorpPortal/              # Aplicação web (único projeto de produção)
│   ├── Program.cs                     # Composição: serviços + pipeline HTTP
│   ├── Configuration/                 # Papéis, policies, opções, registro de DI, eventos do cookie
│   ├── Controllers/                   # Controllers MVC (páginas)
│   │   └── Api/                       # Controllers REST (/api/*)
│   ├── Data/                          # AppDbContext, seed e inicialização do banco
│   ├── DTOs/                          # Contratos de entrada/saída da API
│   ├── Extensions/                    # Extensões de HttpContext e ClaimsPrincipal
│   ├── Lab/                           # Ponto de extensão do futuro laboratório (vazio)
│   ├── Logging/                       # Serilog, formatter JSON, nomes de campos, redação
│   ├── Middleware/                    # Correlação, request logging, headers, exceções
│   ├── Migrations/                    # Migrations do EF Core (geradas por dotnet-ef)
│   ├── Models/                        # Entidades (User, Role, Document, AuditEvent) e enums
│   │   └── ViewModels/                # Modelos específicos das Views
│   ├── Repositories/                  # Acesso a dados de documentos e auditoria
│   ├── Services/                      # Regras de negócio
│   ├── Views/                         # Razor Views
│   ├── wwwroot/                       # CSS e JS estáticos
│   ├── appsettings.json               # Configuração base (produção/Docker)
│   └── appsettings.Development.json   # Configuração para "dotnet run"
├── tests/SecureCorpPortal.Tests/      # Testes unitários e de integração (xUnit)
├── docs/
│   ├── architecture/                  # Arquitetura, fluxo, modelo de dados, logging
│   ├── security/                      # Permissões, controles atuais, pontos de extensão
│   └── siem/                          # Esquema de log, catálogo de eventos, detecções
├── logs/                              # Logs JSON gerados pela aplicação
├── Dockerfile
├── docker-compose.yml                 # App + PostgreSQL (+ perfil "test")
├── docker-compose.dev.yml             # Publica o PostgreSQL em 127.0.0.1 para "dotnet run"
└── .env.example
```

**Por que `src/` e `tests/` separados?** É o layout padrão de soluções .NET. Se a pasta `Tests/`
ficasse dentro do projeto web, o SDK compilaria os testes junto com a aplicação (e eles iriam
para a imagem Docker). Com projetos separados, a aplicação publicada contém apenas código de produção.

**Por que os uploads não ficam em `wwwroot/uploads`?** Tudo em `wwwroot` é servido diretamente
pelo `StaticFiles`, **sem passar pela autorização**. Os arquivos ficam em `data/uploads`
(fora de `wwwroot`) e só são entregues pelo endpoint de download, que verifica as permissões.

## 5. Requisitos

**Para executar com Docker (recomendado):**
- Docker Desktop (Windows/macOS) ou Docker Engine + Compose v2 (Linux)

**Para desenvolver/executar sem Docker:**
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- PostgreSQL 16 (ou o container do `docker-compose.dev.yml`)
- Opcional: `dotnet tool install --global dotnet-ef --version 8.0.11`

## 6. Instalação e execução

### Opção A — Docker Compose (tudo em containers)

```bash
docker compose up -d --build
```

Acesse **http://localhost:8080** e entre com um dos [usuários de teste](#9-usuários-de-teste).

### Opção B — `dotnet run` + PostgreSQL em container

```bash
# 1. sobe apenas o banco, publicado em 127.0.0.1:5432
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d db

# 2. executa a aplicação (ambiente Development)
dotnet run --project src/SecureCorpPortal
```

Acesse **http://localhost:5080**. No ambiente Development a aplicação usa
`appsettings.Development.json`: migrations e seed automáticos, logs em `./logs`, uploads em `./data/uploads`.

## 7. Docker

| Serviço | Imagem | Função | Rede |
|---|---|---|---|
| `db` | `postgres:16-alpine` | Banco de dados | `backend` (interna, sem porta publicada) |
| `web` | build do `Dockerfile` | Aplicação ASP.NET Core | `backend` + `frontend` (porta em `127.0.0.1:8080`) |
| `tests` | `dotnet/sdk:8.0` | Executa a suíte de testes (perfil `test`) | padrão |

Comandos úteis:

```bash
docker compose up -d --build                     # iniciar
docker compose logs -f web                       # acompanhar logs (JSON) da aplicação
docker compose down                              # parar (mantém banco e uploads)
docker compose down -v                           # parar e APAGAR banco/uploads (reset completo)
docker compose --profile test run --rm tests     # executar os testes
```

Personalização (porta, senha do banco, seed): copie `.env.example` para `.env`.

Detalhes do `Dockerfile`:
- build multi-stage (SDK para compilar, `aspnet` apenas com runtime na imagem final);
- executa como usuário **não-root** (`$APP_UID`, padrão das imagens .NET 8);
- volumes: `./logs` → `/app/logs` (logs no host) e `appdata` → `/app/data` (uploads e chaves de Data Protection).

> **Linux:** o container grava em `./logs` com o UID 1654. Se aparecer erro de permissão,
> execute `sudo chown -R 1654:1654 logs` (ou `chmod 777 logs` no laboratório).

## 8. Banco de dados

### Entidades

| Entidade | Tabela | Descrição |
|---|---|---|
| `ApplicationUser` ("User") | `users` | Estende `IdentityUser<int>`: nome, departamento, cargo, ativo, último login |
| `ApplicationRole` ("Role") | `roles` | Estende `IdentityRole<int>` com descrição |
| — | `user_roles` | Associação N:N usuário ↔ papel (cada usuário tem **um** papel) |
| `Document` | `documents` | Título, descrição, classificação, conteúdo **ou** arquivo, dono |
| `AuditEvent` | `audit_events` | Trilha de auditoria (sem FK, sobrevive à exclusão do usuário) |

Tabelas auxiliares do Identity: `user_claims`, `user_logins`, `user_tokens`, `role_claims`.

### Relacionamentos

- `users` 1 ─── N `documents` (`documents.OwnerId`, **ON DELETE SET NULL**)
- `users` N ─── N `roles` via `user_roles`
- `audit_events.UserId` apenas **referencia** o usuário (sem chave estrangeira, de propósito)

Diagrama e detalhes: [docs/architecture/data-model.md](docs/architecture/data-model.md).

### Migrations

As migrations ficam em `src/SecureCorpPortal/Migrations` e são **aplicadas automaticamente**
na inicialização (`Data/DatabaseInitializer.cs`). Para criar uma nova após alterar o modelo:

```bash
dotnet ef migrations add NomeDaMudanca --project src/SecureCorpPortal
dotnet ef database update --project src/SecureCorpPortal   # opcional: a app aplica sozinha
```

### Seed (dados iniciais)

Com `Seed:Enabled=true` (padrão no Docker e em Development), `Data/DatabaseSeeder.cs` cria os 4 papéis,
6 usuários e 10 documentos fictícios. O seed é idempotente (só cria o que falta). O seed não usa
`HasData()` porque usuários precisam de hash de senha e campos normalizados gerados pelo Identity.

### Resetar o banco

```bash
docker compose down -v && docker compose up -d --build
```

## 9. Usuários de teste

| Usuário | Senha | Papel | Nome | Departamento |
|---|---|---|---|---|
| `admin` | `Admin@123!` | ADMIN | Carla Mendes | Tecnologia da Informação |
| `analyst` | `Analyst@123!` | ANALYST | Rafael Souza | Segurança da Informação |
| `employee` | `Employee@123!` | EMPLOYEE | Juliana Lima | Financeiro |
| `guest` | `Guest@123!` | GUEST | Pedro Alves | Parceiros Externos |
| `marcos.oliveira` | `Employee@123!` | EMPLOYEE | Marcos Oliveira | Comercial |
| `patricia.santos` | `Employee@123!` | EMPLOYEE | Patrícia Santos | Recursos Humanos |

Novos cadastros (`/register`) recebem sempre o papel **GUEST**.

## 10. Permissões

| Funcionalidade | ADMIN | ANALYST | EMPLOYEE | GUEST |
|---|:-:|:-:|:-:|:-:|
| Dashboard e próprio perfil | ✅ | ✅ | ✅ | ✅ |
| Documentos **Public** | ✅ | ✅ | ✅ | ✅ |
| Documentos **Internal** | ✅ | ✅ | ✅ | ❌ |
| Documentos **Confidential** | ✅ | ✅ | ❌ | ❌ |
| Documentos **Restricted** | ✅ | ❌ | ❌ | ❌ |
| Publicar documentos (até o próprio nível) | ✅ | ✅ | ✅ | ❌ |
| Excluir documentos | ✅ | ❌ | ❌ | ❌ |
| Diretório de usuários (leitura) | ✅ | ✅ | ❌ | ❌ |
| Indicadores de segurança no dashboard | ✅ | ✅ | ❌ | ❌ |
| Gerenciar usuários (papel, status, exclusão, desbloqueio) | ✅ | ❌ | ❌ | ❌ |
| Área administrativa e eventos de auditoria | ✅ | ❌ | ❌ | ❌ |

O dono de um documento sempre consegue lê-lo. Matriz completa e onde cada regra está implementada:
[docs/security/permissions.md](docs/security/permissions.md).

## 11. Páginas

| Rota | Descrição | Acesso |
|---|---|---|
| `/login`, `/register` | Login e cadastro | Público |
| `/dashboard` | Resumo pessoal (+ indicadores para ADMIN/ANALYST) | Autenticado |
| `/profile` | Dados pessoais e troca de senha | Autenticado |
| `/documents` | Lista/filtro de documentos permitidos | Autenticado |
| `/documents/{id}` | Detalhes, download e exclusão (ADMIN) | Conforme classificação |
| `/documents/upload` | Publicar arquivo ou texto | ADMIN, ANALYST, EMPLOYEE |
| `/search` | Busca global (documentos; usuários para ADMIN/ANALYST) | Autenticado |
| `/users`, `/users/{id}` | Diretório de usuários | ADMIN, ANALYST |
| `/admin` | Visão geral administrativa | ADMIN |
| `/admin/users` | Gerenciar usuários | ADMIN |
| `/admin/logs` | Eventos de auditoria com filtros | ADMIN |
| `/health` | Health check | Público |

## 12. API REST

A API usa o **mesmo cookie** de autenticação das páginas. Respostas de erro seguem o padrão
`application/problem+json` (RFC 7807). Enums são serializados como texto (ex.: `"Confidential"`).

| Método | Rota | Descrição | Acesso |
|---|---|---|---|
| POST | `/api/auth/login` | Autentica e emite o cookie | Público |
| POST | `/api/auth/register` | Cria conta (GUEST) | Público |
| POST | `/api/auth/logout` | Encerra a sessão | Autenticado |
| GET | `/api/auth/me` | Usuário atual | Autenticado |
| GET | `/api/users` | Lista usuários | ADMIN, ANALYST |
| GET | `/api/users/{id}` | Detalhes | Próprio usuário, ADMIN, ANALYST |
| PUT | `/api/users/{id}` | Atualiza (papel/status só ADMIN) | Próprio usuário, ADMIN |
| DELETE | `/api/users/{id}` | Exclui | ADMIN |
| GET | `/api/documents?q=` | Lista/busca documentos visíveis | Autenticado |
| GET | `/api/documents/{id}` | Detalhes (auditado) | Conforme classificação |
| GET | `/api/documents/{id}/download` | Download do arquivo | Conforme classificação |
| POST | `/api/documents` | Cria documento textual (JSON) | ADMIN, ANALYST, EMPLOYEE |
| POST | `/api/documents/upload` | Envia arquivo (multipart) | ADMIN, ANALYST, EMPLOYEE |
| DELETE | `/api/documents/{id}` | Exclui | ADMIN |
| GET | `/api/admin/users` | Usuários + dados de bloqueio | ADMIN |
| GET | `/api/admin/logs` | Auditoria (filtros + paginação) | ADMIN |
| GET | `/api/dashboard` | Dados do dashboard | Autenticado |

Exemplos com `curl` (o arquivo `cookies.txt` guarda a sessão):

```bash
# login
curl -c cookies.txt -H "Content-Type: application/json" \
     -d '{"userName":"analyst","password":"Analyst@123!"}' \
     http://localhost:8080/api/auth/login

# documentos visíveis para o analista, filtrando por termo
curl -b cookies.txt "http://localhost:8080/api/documents?q=incidentes"

# criar documento textual
curl -b cookies.txt -H "Content-Type: application/json" \
     -d '{"title":"Checklist SOC","classification":"Confidential","content":"..."}' \
     http://localhost:8080/api/documents

# upload de arquivo
curl -b cookies.txt -F "Title=Relatório" -F "Classification=Internal" -F "File=@relatorio.pdf" \
     http://localhost:8080/api/documents/upload

# auditoria (como admin): falhas de login dos últimos eventos
curl -b admin-cookies.txt "http://localhost:8080/api/admin/logs?eventType=UserLoginFailed&pageSize=20"
```

Status HTTP: `200/201/204` sucesso · `400` validação · `401` não autenticado ·
`403` sem permissão · `404` não encontrado · `500` erro interno (com `request_id`, sem detalhes internos).

## 13. Logs

- **Formato:** JSON Lines (um objeto JSON por linha), campos em `snake_case`.
- **Local:** `logs/` na raiz do repositório (Docker e `dotnet run`).
- **Arquivos:** `securecorp-AAAAMMDD.json` (tudo) e `security-AAAAMMDD.json` (somente auditoria/segurança).
- **Rotação:** diária, 14 arquivos retidos.
- **Campos:** `timestamp`, `level`, `severity`, `message`, `event_type`, `event_category`, `action`,
  `outcome`, `request_id`, `source_ip`, `user_id`, `username`, `http_method`, `endpoint`,
  `status_code`, `duration_ms`, `user_agent`, `resource`, `trace_id`, `properties`, `exception`.
- **Nunca registrados:** senhas, tokens, cookies, connection strings. Além de nunca passarmos esses
  valores ao logger, o formatter mascara (`[REDACTED]`) qualquer propriedade com nome sensível.
- **Correlação:** todo evento de uma requisição tem o mesmo `request_id`, devolvido ao cliente no
  header `X-Request-ID` e exibido nas páginas de erro.

Exemplo real (evento de auditoria):

```json
{"timestamp":"2026-10-01T00:15:25.244Z","level":"Warning","severity":"medium","message":"Audit UserLoginFailed: auth.login [failure]","event_type":"UserLoginFailed","event_category":"audit","action":"auth.login","outcome":"failure","request_id":"74e2340b29b74bcb97d58ca3f16f3ae9","source_ip":"172.19.0.1","user_id":3,"username":"employee","http_method":"POST","endpoint":"/api/auth/login","user_agent":"Mozilla/5.0 ...","properties":{"audit_id":3,"details":"Senha inválida."}}
```

Esquema completo: [docs/siem/log-schema.md](docs/siem/log-schema.md) ·
Estratégia: [docs/architecture/logging-strategy.md](docs/architecture/logging-strategy.md).

## 14. Auditoria

Além do log técnico, eventos de negócio importantes são gravados na tabela `audit_events`
**e** emitidos no log com `event_category = "audit"`.

| Evento | Quando |
|---|---|
| `UserLogin` / `UserLoginFailed` / `UserLockedOut` / `UserLogout` | Autenticação |
| `UserCreated` / `UserUpdated` / `UserDeleted` | Ciclo de vida de contas |
| `RoleChanged` | Papel alterado por um ADMIN |
| `PasswordChanged` | Troca de senha (sucesso ou falha) |
| `DocumentAccessed` / `DocumentDownloaded` | Leitura de documento |
| `DocumentCreated` / `DocumentUploaded` / `DocumentDeleted` | Escrita de documentos (inclui uploads rejeitados) |
| `AdminAction` | Ativar/desativar/desbloquear conta, consultar a auditoria |
| `AccessDenied` | Negação por policy **ou** por regra de recurso |

Consulte em **/admin/logs** (filtros por tipo, severidade, usuário, resultado e período) ou via
`GET /api/admin/logs`. Catálogo com severidades: [docs/siem/event-catalog.md](docs/siem/event-catalog.md).

## 15. Testes

188 testes (xUnit) cobrindo autenticação, usuários, permissões, documentos, upload, API, páginas MVC,
logging e auditoria. Os testes sobem a aplicação real em memória (`WebApplicationFactory`) com
banco EF Core InMemory — **não precisam de PostgreSQL**.

```bash
# com .NET 8 SDK instalado
dotnet test

# sem .NET instalado (usa um container com o SDK)
docker compose --profile test run --rm tests
```

| Pasta | Conteúdo |
|---|---|
| `Api/` | Login, cadastro, lockout, CRUD de usuários, documentos, upload, admin, dashboard |
| `Security/` | Matriz papel × endpoint (API e páginas) e acesso anônimo |
| `Web/` | Páginas MVC, antiforgery, open redirect, headers de segurança, páginas de erro |
| `Audit/` | Cada ação relevante gera o evento de auditoria correto, sem senhas |
| `Logging/` | Formato JSON, redação de dados sensíveis, correlação por `request_id`, arquivos em disco |
| `Unit/` | `DocumentAccessPolicy`, severidades, normalização de papéis, sanitização |

Dica: `SECURECORP_KEEP_TEST_FILES=1 dotnet test` preserva os logs gerados pelos testes
(no diretório temporário `securecorp-tests/`) para inspeção.

## 16. Futuro laboratório de segurança

Nesta etapa **nenhum módulo de laboratório foi implementado**. A aplicação usa os controles
de segurança padrão descritos em [docs/security/security-baseline.md](docs/security/security-baseline.md).

A arquitetura já prevê onde os módulos serão conectados:

- `Lab/ILabModule.cs` + `Lab/SecurityLabExtensions.cs`: contrato e registro de módulos isolados,
  desabilitados por padrão (`SecurityLab:Enabled=false`), com rotas próprias sob `/lab/{id}`;
- comentários `LAB-EXTENSION-POINT` no código, mapeados em
  [docs/security/extension-points.md](docs/security/extension-points.md);
- modelo de ficha de exercício em [docs/security/exercise-template.md](docs/security/exercise-template.md);
- eventos e detecções conceituais para o SOC em [docs/siem/](docs/siem/README.md).

## 17. Documentação complementar

| Documento | Conteúdo |
|---|---|
| [architecture/overview.md](docs/architecture/overview.md) | Camadas, responsabilidades e decisões |
| [architecture/request-flow.md](docs/architecture/request-flow.md) | Pipeline de middlewares e fluxos principais |
| [architecture/data-model.md](docs/architecture/data-model.md) | Entidades, relacionamentos, migrations e seed |
| [architecture/logging-strategy.md](docs/architecture/logging-strategy.md) | Como logs e auditoria são produzidos |
| [security/permissions.md](docs/security/permissions.md) | Matriz de permissões detalhada |
| [security/security-baseline.md](docs/security/security-baseline.md) | Controles de segurança implementados |
| [security/extension-points.md](docs/security/extension-points.md) | Onde cada tema de segurança se conecta ao código |
| [security/exercise-template.md](docs/security/exercise-template.md) | Modelo para documentar exercícios futuros |
| [siem/log-schema.md](docs/siem/log-schema.md) | Esquema dos eventos JSON |
| [siem/event-catalog.md](docs/siem/event-catalog.md) | Tipos de evento e severidades |
| [siem/detection-use-cases.md](docs/siem/detection-use-cases.md) | Ideias de detecção, correlação e dashboards |
| [siem/integration-guide.md](docs/siem/integration-guide.md) | Como enviar os logs a um SIEM no futuro |
