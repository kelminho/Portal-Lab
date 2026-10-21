# Modelo de dados

## Diagrama

```
┌──────────────────────────┐        ┌───────────────────┐        ┌────────────────────────┐
│ users (ApplicationUser)  │        │ user_roles        │        │ roles (ApplicationRole)│
├──────────────────────────┤        ├───────────────────┤        ├────────────────────────┤
│ Id (PK, int)             │◄──────┤│ UserId (PK, FK)   ││──────►│ Id (PK, int)           │
│ UserName / Normalized…   │ 1    N │ RoleId (PK, FK)   │ N    1 │ Name / NormalizedName  │
│ Email / Normalized…      │        └───────────────────┘        │ Description            │
│ PasswordHash             │                                     └────────────────────────┘
│ SecurityStamp            │
│ LockoutEnd               │        ┌──────────────────────────────┐
│ AccessFailedCount        │        │ documents (Document)         │
│ FullName                 │        ├──────────────────────────────┤
│ Department, JobTitle     │ 1    N │ Id (PK, int)                 │
│ IsActive                 │◄───────│ OwnerId (FK, null, SET NULL) │
│ CreatedAt, LastLoginAt   │        │ Title, Description           │
└──────────────────────────┘        │ Classification (texto)       │
            ▲                       │ Content (texto, opcional)    │
            ┆ referência lógica     │ OriginalFileName             │
            ┆ (sem FK)              │ StoredFileName (GUID.ext)    │
┌──────────────────────────┐        │ ContentType, SizeBytes       │
│ audit_events (AuditEvent)│        │ CreatedAt, UpdatedAt         │
├──────────────────────────┤        └──────────────────────────────┘
│ Id (PK, bigint)          │
│ Timestamp                │   Tabelas auxiliares do Identity (não usadas diretamente):
│ EventType, Action        │   user_claims, user_logins, user_tokens, role_claims
│ Success, Severity        │
│ UserId, Username         │
│ SourceIp, UserAgent      │
│ HttpMethod, Endpoint     │
│ Resource, Details        │
│ RequestId                │
└──────────────────────────┘
```

## Entidades

### `ApplicationUser` → `users`
Herda de `IdentityUser<int>` (chave inteira para facilitar a leitura). O Identity fornece
`PasswordHash` (PBKDF2 com salt), `SecurityStamp` (invalida sessões quando muda),
`LockoutEnd`/`AccessFailedCount` (bloqueio) e campos normalizados para busca sem distinção de caixa.
Campos adicionados: `FullName`, `Department`, `JobTitle`, `IsActive`, `CreatedAt`, `LastLoginAt`.

### `ApplicationRole` → `roles`
Herda de `IdentityRole<int>` com `Description`. Valores: `ADMIN`, `ANALYST`, `EMPLOYEE`, `GUEST`.
O relacionamento é N:N (`user_roles`), mas a aplicação mantém **um papel por usuário**
(ao trocar o papel, remove os anteriores).

### `Document` → `documents`
- `Classification`: `Public` < `Internal` < `Confidential` < `Restricted`, gravado como **texto**
  (fica legível em consultas SQL e no SIEM).
- Pode ser textual (`Content`) ou arquivo (`StoredFileName` + metadados). O nome em disco é gerado
  pelo servidor; o nome original serve só para exibição e download.
- `OwnerId` com `ON DELETE SET NULL`: excluir um usuário não apaga os documentos dele.

### `AuditEvent` → `audit_events`
Trilha de auditoria. **Não tem chave estrangeira** para `users`: os eventos precisam sobreviver à
exclusão do usuário, e `Username` é copiado no momento do evento. Índices em `Timestamp`,
`EventType` e `UserId` para as consultas da tela `/admin/logs`.

## Migrations

| Item | Local |
|---|---|
| Modelo | `Data/AppDbContext.cs` (`OnModelCreating`) |
| Migrations | `Migrations/*_InitialCreate.cs` + `AppDbContextModelSnapshot.cs` |
| Aplicação | Automática na inicialização (`Data/DatabaseInitializer.cs`, com novas tentativas enquanto o banco sobe) |

Criar uma nova migration após alterar entidades ou o `OnModelCreating`:

```bash
dotnet tool install --global dotnet-ef --version 8.0.11   # uma vez
dotnet ef migrations add AdicionaCampoX --project src/SecureCorpPortal
```

Sem .NET instalado, gere dentro de um container:

```bash
docker run --rm -v "$PWD:/src" -w /src mcr.microsoft.com/dotnet/sdk:8.0 bash -c \
  "dotnet tool install -g dotnet-ef --version 8.0.11 && export PATH=\$PATH:/root/.dotnet/tools && \
   dotnet ef migrations add AdicionaCampoX --project src/SecureCorpPortal"
```

Ver o SQL que uma migration gera: `dotnet ef migrations script --project src/SecureCorpPortal`.

## Seed (dados iniciais)

`Data/DatabaseSeeder.cs`, executado quando `Seed:Enabled=true`:

| Tipo | Quantidade | Observação |
|---|---|---|
| Papéis | 4 | Com descrição das permissões |
| Usuários | 6 | Definidos em `Data/DemoAccounts.cs` (senhas públicas de laboratório) |
| Documentos | 10 | 3 Public, 3 Internal, 2 Confidential, 2 Restricted, com donos variados |

É idempotente: roda a cada inicialização, mas só cria o que não existe. Para recomeçar do zero:
`docker compose down -v`.

## Consultas úteis (psql)

```bash
docker exec -it securecorp-db psql -U securecorp -d securecorp
```

```sql
-- usuários e papéis
SELECT u."UserName", r."Name" AS role, u."IsActive"
FROM users u JOIN user_roles ur ON ur."UserId" = u."Id" JOIN roles r ON r."Id" = ur."RoleId";

-- documentos por classificação
SELECT "Classification", count(*) FROM documents GROUP BY 1;

-- últimas falhas de login
SELECT "Timestamp", "Username", "SourceIp", "Details"
FROM audit_events WHERE "EventType" = 'UserLoginFailed' ORDER BY "Timestamp" DESC LIMIT 20;
```

> As colunas usam PascalCase (padrão do EF Core), por isso precisam de aspas no PostgreSQL.
