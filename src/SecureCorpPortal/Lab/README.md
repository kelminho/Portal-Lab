# Lab/ — ponto de extensão para o laboratório de segurança

Esta pasta está **reservada** para os futuros módulos educacionais de segurança.
Nesta primeira etapa **nenhum módulo foi implementado**. A aplicação funciona
integralmente com os controles de segurança padrão descritos em
`docs/security/security-baseline.md`.

## Conteúdo atual

| Arquivo | Finalidade |
|---|---|
| `ILabModule.cs` | Contrato que todo módulo futuro deverá implementar |
| `SecurityLabExtensions.cs` | Registro/ativação dos módulos, opções `SecurityLab:*` e catálogo exibido em `/admin` |

## Princípios para módulos futuros

1. **Isolamento** – cada módulo em `Lab/Modules/<Id>/`, sem alterar controllers/services principais.
2. **Desligado por padrão** – só é ativado com `SecurityLab:Enabled=true` **e** o Id em `SecurityLab:EnabledModules`.
3. **Rotas próprias** – endpoints sempre sob `/lab/{id}/...`, facilmente identificáveis nos logs.
4. **Rastreável** – o startup registra um evento `SecurityLabEnabled` (severidade alta) listando os módulos ativos.
5. **Documentado** – cada módulo terá uma ficha baseada em `docs/security/exercise-template.md`.
6. **Somente laboratório** – nunca habilitar fora do ambiente isolado.

Veja `docs/security/extension-points.md` para o mapa de onde cada tema
(autenticação, autorização, upload, logging…) se conecta ao código.
