# Visão geral da arquitetura

## Estilo

**Monólito em camadas**: um único projeto ASP.NET Core atende as páginas Razor (MVC) e a API REST,
compartilhando os mesmos services, autenticação, autorização, auditoria e logging. É simples de
executar, depurar e estudar. Não há microserviços, mensageria ou frameworks de frontend.

## Camadas e responsabilidades

| Camada | Pasta | Responsabilidade | Não deve |
|---|---|---|---|
| Apresentação (páginas) | `Controllers/`, `Views/`, `Models/ViewModels/` | Receber formulários, validar entrada, renderizar HTML | Conter regra de negócio ou acessar o banco |
| Apresentação (API) | `Controllers/Api/`, `DTOs/` | Receber/retornar JSON, traduzir resultados em status HTTP | Expor entidades diretamente |
| Negócio | `Services/` | Regras, autorização por recurso, auditoria | Conhecer HTTP (status codes, views) |
| Acesso a dados | `Repositories/`, `Data/` | Consultas EF Core, persistência, seed | Tomar decisões de permissão |
| Transversal | `Middleware/`, `Logging/`, `Configuration/`, `Extensions/` | Pipeline, logs, configuração, DI | — |
| Extensão futura | `Lab/` | Contrato para módulos de laboratório (vazio) | Alterar o comportamento padrão |

## Decisões principais

### 1. MVC + API no mesmo projeto
Páginas e API usam os mesmos services. Assim, uma regra (ex.: "EMPLOYEE não lê documentos
Confidential") é implementada **uma vez** e vale para os dois canais. Os testes verificam ambos.

### 2. ASP.NET Core Identity com cookie
O Identity já resolve hash de senha (PBKDF2), bloqueio por tentativas, security stamp e
normalização de usuário/e-mail. A autenticação usa um cookie `HttpOnly` + `SameSite=Strict`,
compartilhado por páginas e API. Para chamadas `/api/*`, os redirecionamentos do cookie são
trocados por respostas `401`/`403` em JSON (`Configuration/AuthenticationEventHandlers.cs`).

### 3. Autorização em dois níveis
1. **Por endpoint** (policies em `Configuration/Policies.cs`): "quem pode chamar esta rota?".
   Há uma *fallback policy*: qualquer endpoint sem anotação exige login.
2. **Por recurso** (`Services/DocumentAccessPolicy.cs` e regras no `UserService`):
   "este usuário pode ver *este* documento / alterar *este* usuário?".

### 4. Services retornam `ServiceResult`, não exceções nem status HTTP
`ServiceResult` carrega `Success`, `NotFound`, `Forbidden`, `Invalid` ou `Conflict`.
Os controllers MVC transformam isso em páginas; os controllers da API, em `ProblemDetails`.

### 5. DTOs explícitos
A API nunca devolve entidades. `UserDto` não contém `PasswordHash`/`SecurityStamp`;
`UpdateUserRequest` só aceita campos permitidos (proteção contra *mass assignment*);
listagens de documentos não incluem o conteúdo.

### 6. Repositórios apenas onde agregam valor
Documentos e auditoria têm repositórios. Para usuários, o `UserManager` do Identity já faz o
papel de repositório (valida, normaliza, persiste), então o `UserService` o usa diretamente.

### 7. Auditoria separada do log técnico
`AuditService` grava na tabela `audit_events` (consultável pela aplicação) **e** emite no log JSON.
A gravação usa um `DbContext` próprio (novo escopo de DI) para ser independente da operação de negócio.

### 8. Logging estruturado com formatter próprio
`SiemJsonFormatter` gera JSON com nomes de campo estáveis, promovidos ao nível superior, e mascara
propriedades sensíveis. Ver [logging-strategy.md](logging-strategy.md).

### 9. Uploads fora de `wwwroot`
Arquivos em `wwwroot` são servidos sem autorização. Uploads ficam em `data/uploads` com nome
aleatório e só saem pelo endpoint de download, que verifica permissões e registra auditoria.

### 10. Configuração por ambiente
| Arquivo / variável | Uso |
|---|---|
| `appsettings.json` | Base segura: sem connection string, seed desligado |
| `appsettings.Development.json` | `dotnet run`: PostgreSQL local, seed ligado, logs em `../../logs` |
| Variáveis do `docker-compose.yml` | Docker: connection string, seed, diretórios `/app/logs` e `/app/data` |
| Testes (`PortalWebApplicationFactory`) | Banco InMemory, diretório temporário para logs/uploads |

Variáveis de ambiente usam `__` como separador: `ConnectionStrings__DefaultConnection`, `Seed__Enabled`.

## Diagrama de componentes

```
┌──────────────────────────────── SecureCorpPortal (processo único) ───────────────────────────────┐
│                                                                                                   │
│  Views (Razor) ◄── Controllers MVC ──┐                 ┌── Controllers API ──► JSON               │
│                                      ▼                 ▼                                          │
│                      ┌───────────────────────────────────────────────┐                            │
│                      │                  Services                     │                            │
│                      │ AuthService      UserService    DocumentService│                           │
│                      │ DashboardService AuditService   FileStorage    │                           │
│                      │ DocumentAccessPolicy (regras de acesso)        │                           │
│                      └───────┬──────────────┬───────────────┬────────┘                            │
│                              ▼              ▼               ▼                                     │
│                   UserManager/RoleManager  Repositories   Disco (data/uploads)                    │
│                              └──────┬───────┘                                                     │
│                                     ▼                                                             │
│                            AppDbContext (EF Core) ───────────────► PostgreSQL                     │
│                                                                                                   │
│  Middleware: Correlation · ExceptionHandler · SecurityHeaders · RequestLogging                    │
│  Serilog ─► logs/securecorp-*.json, logs/security-*.json, console                                 │
│  Lab/ (ILabModule) ─► nenhum módulo registrado                                                    │
└───────────────────────────────────────────────────────────────────────────────────────────────────┘
```
