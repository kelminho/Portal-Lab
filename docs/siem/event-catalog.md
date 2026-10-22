# Catálogo de eventos

`event_category = audit` também é gravado na tabela `audit_events` (consulta em `/admin/logs`).
Em falha (`outcome = failure`) a severidade é no mínimo `medium`.

## Auditoria (`event_category = audit`)

| `event_type` | Severidade | Quando |
|---|---|---|
| `UserLogin` | info | Login bem-sucedido (`action = auth.login`) |
| `UserLoginFailed` | medium | Falha de login. `properties.details`: `Usuário inexistente.`, `Senha inválida.`, `Conta desativada.` ou `Login não permitido para esta conta.` |
| `UserLockedOut` | high | 5 falhas seguidas → bloqueio de 15 min (`action = auth.lockout`) |
| `UserLogout` | info | Logout |
| `UserCreated` | low | Conta criada (cadastro é sempre GUEST) |
| `UserUpdated` | low | Dados de usuário alterados |
| `UserDeleted` | high | Conta excluída por ADMIN |
| `RoleChanged` | high | Papel alterado por ADMIN |
| `PasswordChanged` | medium | Troca de senha (sucesso ou falha) |
| `DocumentAccessed` | info | Detalhes de um documento |
| `DocumentDownloaded` | info | Download de arquivo |
| `DocumentCreated` | low | Documento textual criado |
| `DocumentUploaded` | low | Upload (inclui rejeitados, com `outcome = failure`) |
| `DocumentDeleted` | medium | Exclusão por ADMIN |
| `AdminAction` | medium | Ativar/desativar/desbloquear conta, consulta à auditoria |
| `AccessDenied` | medium | Negação por papel/policy ou por regra de recurso. `action`: `authorization.policy_denied`, `document.read_denied`, `document.download_denied`, `document.create_denied`, `document.delete_denied`, `user.read_denied`, `user.update_denied`, `user.privilege_change_denied` (high), `user.delete_denied` (high), `csrf.validation_failed` (POST de formulário sem token antiforgery válido), `login.external_return_url_blocked` (`returnUrl` externo ignorado após login) |

O valor exato de `action` de cada evento está no código dos services (`Services/*.cs`).

## Segurança técnica (`event_category = security`)

| `event_type` | Severidade | Quando |
|---|---|---|
| `AuthenticationRequired` | conforme `level` | Acesso a recurso protegido sem sessão |
| `AuditPersistenceFailed` | high | Falha ao gravar a auditoria no banco |
| `SecurityLabEnabled` | high | Módulos do laboratório ativados na inicialização |

## Aplicação e tráfego

| `event_type` | `event_category` | Severidade | Quando |
|---|---|---|---|
| `HttpRequest` | `http` | info (2xx/3xx/4xx), medium (401/403), high (5xx) | Uma linha por requisição (exceto estáticos) |
| `ApplicationError` | `application` | high | Exceção não tratada (resposta 500 genérica) |
| `DatabaseInitialization` | `application` | info | Migrations e seed na inicialização |

Observação: `404` aparece como `HttpRequest` com severidade `info`; varreduras de diretório
precisam ser detectadas por contagem (ver [detection-use-cases.md](detection-use-cases.md)).
