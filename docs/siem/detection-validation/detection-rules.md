# Catálogo de regras de detecção (CQL) — Falcon Next-Gen SIEM

> **Status: propostas não executadas.** Nenhuma consulta abaixo foi rodada em um tenant do Falcon NG-SIEM
> (sem acesso). Os nomes de campo e os valores (`event_type`, `action`, `details`…) foram conferidos no
> código e nos logs reais de [`evidence/20261022T210231Z/`](evidence/20261022T210231Z/); a **sintaxe CQL** foi escrita
> a partir da documentação do LogScale e precisa ser validada em *Advanced event search* antes de virar regra de correlação.
> Este repositório não contém parser, conector nem regras do SIEM; nada existente foi alterado.

Complementa [`../detection-use-cases.md`](../detection-use-cases.md) (casos genéricos, mantidos). Aqui estão apenas as regras ligadas
aos testes T-01…T-28, com limiar, falsos positivos e procedimento de validação. A matriz está em [`test-matrix.md`](test-matrix.md).

## Convenções

- **Premissas de ingestão:** o JSON de cada linha é parseado (`parseJson`), `timestamp` vira `@timestamp`, e os objetos aninhados ficam
  com nome pontuado (`properties.details`, `properties.request_id_rejected`). Sem isso, ajuste os nomes. Esboço de parser no [runbook §5](execution-runbook.md#5-ingestão-no-falcon-ng-siem).
- **Filtro-base:** `application=SecureCorpPortal` (campo constante em todas as linhas). Acrescente o filtro do repositório/dataset do seu tenant.
- **Arquivo de origem:** auditoria e segurança estão nos dois arquivos; ingira `security-*.json` **e** `securecorp-*.json` mas sem duplicar
  (as regras `HttpRequest` precisam do segundo). Se ingerir os dois, deduplique por `request_id` + `event_type` + `timestamp`.
- **Janela e frequência** são configurações da regra de correlação (janela de busca + agendamento), não parte da consulta.
  Padrão adotado: janela = período da coluna *Janela*, execução a cada 1 min.
- **Limiar lab / prod:** onde aparecem dois valores, o de laboratório é o que faz a regra disparar com o volume dos testes executados.
- **Severidade:** Informational, Low, Medium, High ou Critical (escala do NG-SIEM).
- `request_id` de teste: `PT-<teste>-<RUN_ID>-<seq>` (ver [runbook §2](execution-runbook.md#2-convenções-de-correlação)).

## Índice

| Regra | Nome | Testes |
|---|---|---|
| DR-01 | Força bruta por conta e IP | T-07 |
| DR-02 | Conta bloqueada | T-07 |
| DR-03 | Password spraying | T-08 |
| DR-04 | Enumeração de usuários no login | T-21 |
| DR-05 | Login com sucesso após falhas | T-07 (extensão manual) |
| DR-06 | Negações de acesso em recursos distintos (IDOR) | T-01, T-02, T-03 |
| DR-07 | Varredura sequencial de IDs | T-01, T-02 |
| DR-08 | Tentativa de escalonamento de privilégio bloqueada | T-04, T-05 |
| DR-09 | Troca de papel por ator fora da lista de admins | T-04 (extensão manual) |
| DR-10 | Negações de policy / BFLA | T-06, T-24, T-28 |
| DR-11 | Reuso de sessão após logout | T-09 |
| DR-12 | Rajada de uploads rejeitados | T-12, T-13, T-15 |
| DR-13 | Upload com extensão perigosa ou nome com travessia | T-12, T-14 |
| DR-14 | Requisição de upload acima do limite | T-15 |
| DR-15 | Padrões de injection / XSS / traversal na query | T-16 |
| DR-16 | CSRF: falha de antiforgery e escrita cross-site | T-10, T-11 |
| DR-17 | Open redirect no login | T-18 |
| DR-18 | Abuso e enumeração no cadastro | T-19, T-20 |
| DR-19 | Username fora do padrão (senha digitada no campo) | T-26 |
| DR-20 | `X-Request-ID` rejeitado | T-25 |
| DR-21 | Status HTTP anômalo e erros em série | T-22 |
| DR-22 | Rajadas de 401 e de 404 | T-24 |
| DR-23 | Consulta à trilha de auditoria | T-27 |
| DR-24 | Acesso em massa a documentos | T-01 (varreduras maiores) |
| DR-25 | Visão de correlação do tráfego de teste (auxiliar, não alerta) | todos |

Sem regra possível (telemetria insuficiente): **T-17** (corpo não registrado) e **T-23** (teste passivo). Ver [`telemetry-gaps.md`](telemetry-gaps.md).

---

## DR-01 — Força bruta por conta e IP

| | |
|---|---|
| Objetivo | Muitas falhas contra a mesma conta a partir do mesmo IP |
| Testes | T-07 |
| Campos obrigatórios | `event_type`, `source_ip`, `username` |
| Janela / execução | 5 min / 1 min |
| Limiar | `attempts >= 5` (lab e prod). A 5ª falha **já é** `UserLockedOut`, por isso a soma dos dois tipos |
| Severidade | High |
| Falsos positivos | Usuário que esqueceu a senha; NAT corporativo compartilhado |
| Evidência esperada | T-07: 6 eventos (4 `UserLoginFailed` + 2 `UserLockedOut`) para `pt.lock.<RUN>` |
| Validação | Rodar `ONLY="T-07"`; consulta no intervalo do teste deve retornar 1 linha, `attempts=6` |

```
application=SecureCorpPortal
| in(field=event_type, values=[UserLoginFailed, UserLockedOut])
| groupBy([source_ip, username], function=[count(as=attempts), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| attempts >= 5
```

## DR-02 — Conta bloqueada

| | |
|---|---|
| Objetivo | Registrar todo bloqueio e a insistência durante o bloqueio |
| Testes | T-07 |
| Campos obrigatórios | `event_type`, `username`, `source_ip` |
| Janela / execução | 15 min (duração do lockout) / 1 min |
| Limiar | `lockout_events >= 1` → High; `>= 2` indica tentativas **durante** o bloqueio |
| Severidade | High |
| Falsos positivos | Negação de serviço intencional contra uma conta de terceiro (F-02) é comportamento malicioso, não falso positivo |
| Evidência esperada | T-07: `lockout_events=2` |
| Validação | Idem DR-01 |

```
application=SecureCorpPortal event_type=UserLockedOut
| groupBy([username], function=[count(as=lockout_events), count(source_ip, distinct=true, as=sources), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
```

## DR-03 — Password spraying

| | |
|---|---|
| Objetivo | Uma origem tentando poucas senhas contra muitas contas (a aplicação não limita por IP) |
| Testes | T-08 |
| Campos obrigatórios | `event_type`, `source_ip`, `user_agent`, `username` |
| Janela / execução | 10 min / 1 min |
| Limiar | `distinct_users >= 4` |
| Severidade | High |
| Falsos positivos | Várias pessoas atrás do mesmo NAT errando senha; túnel SSH compartilhado (agrupar também por `user_agent`, já feito) |
| Evidência esperada | T-08: `distinct_users=6`, `attempts=6` |
| Validação | `ONLY="T-08"`; 1 linha com os 6 usernames |

```
application=SecureCorpPortal event_type=UserLoginFailed
| groupBy([source_ip, user_agent], function=[count(username, distinct=true, as=distinct_users), count(as=attempts), collect([username], limit=20)])
| distinct_users >= 4
```

## DR-04 — Enumeração de usuários no login

| | |
|---|---|
| Objetivo | Descobrir quais usuários existem (resposta idêntica ao cliente, mas `details` diferente na auditoria) |
| Testes | T-21 (também T-26) |
| Campos obrigatórios | `event_type`, `properties.details`, `source_ip`, `username` |
| Janela / execução | 10 min / 1 min |
| Limiar | `names_tried >= 3` |
| Severidade | Medium |
| Falsos positivos | Erros de digitação do usuário legítimo (poucos nomes distintos) |
| Evidência esperada | T-21: `names_tried=4` (`ghost.<RUN>.1..4`) |
| Validação | `ONLY="T-21"` |

```
application=SecureCorpPortal event_type=UserLoginFailed properties.details=/inexistente/i
| groupBy([source_ip], function=[count(username, distinct=true, as=names_tried), count(as=attempts), collect([username], limit=10)])
| names_tried >= 3
```

## DR-05 — Login com sucesso após falhas

| | |
|---|---|
| Objetivo | Indício de senha adivinhada: sucesso depois de falhas na mesma conta e IP |
| Testes | Nenhum dos 28 a exercita (T-07 termina bloqueado). Validação manual: 3 senhas erradas e depois a correta com uma conta `pt.*` |
| Campos obrigatórios | `event_type`, `username`, `source_ip` |
| Janela / execução | 10 min / 1 min |
| Limiar | `failures >= 3`, `successes >= 1`, último sucesso depois da última falha |
| Severidade | Critical (consistente com [detection-use-cases.md #5](../detection-use-cases.md)) |
| Falsos positivos | Usuário que errou 3 vezes e acertou |
| Evidência esperada | Nenhuma nos 28 testes (esperado: não dispara) |
| Validação | Procedimento manual acima; **NOT TESTED** |

```
application=SecureCorpPortal
| in(field=event_type, values=[UserLoginFailed, UserLockedOut, UserLogin])
| username=*
| failed := if(event_type == "UserLogin", then=0, else=1)
| okay := if(event_type == "UserLogin", then=1, else=0)
| t_fail := failed * @timestamp
| t_ok := okay * @timestamp
| groupBy([username, source_ip], function=[sum(failed, as=failures), sum(okay, as=successes), max(t_fail, as=last_failure), max(t_ok, as=last_success)])
| failures >= 3
| successes >= 1
| last_success > last_failure
```

## DR-06 — Negações de acesso em recursos distintos (IDOR)

| | |
|---|---|
| Objetivo | Usuário autenticado testando IDs de recursos alheios |
| Testes | T-01, T-02, T-03 |
| Campos obrigatórios | `event_type`, `action`, `resource`, `username`, `source_ip` |
| Janela / execução | 10 min / 1 min |
| Limiar | `distinct_resources >= 3` (lab e prod) |
| Severidade | Medium; High se também disparar DR-07 |
| Falsos positivos | Usuário seguindo links antigos para documentos que perdeu acesso |
| Evidência esperada | T-01: `employee`, 5 recursos (`document:7..11`). T-02: `employee` 5 e `guest` 8. T-03: `employee` 3 (`user:1`, `user:2`, `user:9999`) |
| Validação | `ONLY="T-01 T-02 T-03"` |

```
application=SecureCorpPortal event_type=AccessDenied
| in(field=action, values=["document.read_denied", "document.download_denied", "user.read_denied"])
| groupBy([username, source_ip], function=[count(as=denials), count(resource, distinct=true, as=distinct_resources), collect([resource], limit=15), min(@timestamp, as=first_seen)])
| distinct_resources >= 3
```

## DR-07 — Varredura sequencial de IDs

| | |
|---|---|
| Objetivo | Muitos caminhos `/{recurso}/{n}` distintos em pouco tempo, misturando 200/403/404 (inclui os 404 que não geram auditoria) |
| Testes | T-01, T-02 |
| Campos obrigatórios | `event_type=HttpRequest`, `endpoint`, `status_code`, `username`, `source_ip` |
| Janela / execução | 2 min / 1 min |
| Limiar | `distinct_paths >= 10` |
| Severidade | Medium |
| Falsos positivos | Paginação por IDs numa interface futura; rastreadores internos |
| Evidência esperada | T-01: 16 caminhos (5 com 403, 5 com 404). T-02: 16 por usuário. T-03 tem 4 caminhos e **não** dispara (coberto por DR-06) |
| Validação | `ONLY="T-01 T-02"` |

```
application=SecureCorpPortal event_type=HttpRequest username=*
| endpoint=/^\/(api\/)?(documents|users)\/\d+(\/download)?$/
| nf := if(status_code == 404, then=1, else=0)
| fb := if(status_code == 403, then=1, else=0)
| groupBy([username, source_ip], function=[count(endpoint, distinct=true, as=distinct_paths), sum(nf, as=not_found), sum(fb, as=forbidden), count(as=requests)])
| distinct_paths >= 10
```

## DR-08 — Tentativa de escalonamento de privilégio bloqueada

| | |
|---|---|
| Objetivo | Usuário sem permissão tentando alterar papel/status ou alterar/excluir outra conta |
| Testes | T-04, T-05 |
| Campos obrigatórios | `event_type`, `action`, `username`, `resource`, `severity` |
| Janela / execução | 15 min / 1 min |
| Limiar | `attempts >= 1` |
| Severidade | High para `user.privilege_change_denied`; Medium para os demais |
| Falsos positivos | Pouco prováveis: a UI não expõe esses campos a não-admins |
| Evidência esperada | T-04: `user.privilege_change_denied` ×1 e `user.update_denied` ×1. T-05: `user.privilege_change_denied` ×1 |
| Validação | `ONLY="T-04 T-05"` |

```
application=SecureCorpPortal event_type=AccessDenied
| in(field=action, values=["user.privilege_change_denied", "user.update_denied", "user.delete_denied"])
| groupBy([username, source_ip, action], function=[count(as=attempts), collect([resource], limit=10)])
```

## DR-09 — Troca de papel por ator fora da lista de admins

| | |
|---|---|
| Objetivo | **Exploração confirmada** de escalonamento: `RoleChanged` cujo ator não deveria poder fazê-lo |
| Testes | Nenhum dos 28 produz `RoleChanged`. Validação manual: admin altera o papel de uma conta `pt.*` com `admin` fora da lista |
| Campos obrigatórios | `event_type`, `username` (ator), `properties.details` |
| Janela / execução | 5 min / 1 min |
| Limiar | Qualquer ocorrência |
| Severidade | Critical se `details` contém `para ADMIN`; High nos demais |
| Falsos positivos | Troca legítima por um admin ausente da lista (manter a lista atualizada) |
| Evidência esperada | Nenhuma nos 28 testes |
| Validação | Procedimento manual; **NOT TESTED** |

```
application=SecureCorpPortal event_type=RoleChanged
| not in(field=username, values=["admin"])   // substitua pela lista de administradores legítimos
| table([@timestamp, username, source_ip, resource, properties.details], limit=100)
```

## DR-10 — Negações de policy / BFLA

| | |
|---|---|
| Objetivo | Usuário autenticado tentando funções administrativas ou de outro papel |
| Testes | T-06, T-24, T-28 |
| Campos obrigatórios | `event_type`, `action`, `resource`, `username`, `source_ip` |
| Janela / execução | 10 min / 1 min |
| Limiar | `distinct_resources >= 3`. Um único acesso a `/admin*` por não-admin já merece triagem (Low) |
| Severidade | Medium; High com `distinct_resources >= 5` |
| Falsos positivos | Link de favoritos para página que o usuário perdeu |
| Evidência esperada | T-06: `guest` 8, `employee` 7, `analyst` 5. T-24: `guest` 1 (não dispara, abaixo de 3). T-28: `employee` 1 |
| Validação | `ONLY="T-06"` |

```
application=SecureCorpPortal event_type=AccessDenied action="authorization.policy_denied"
| groupBy([username, source_ip], function=[count(as=denials), count(resource, distinct=true, as=distinct_resources), collect([resource], limit=15)])
| distinct_resources >= 3
```

## DR-11 — Reuso de sessão após logout

| | |
|---|---|
| Objetivo | Cookie de sessão usado depois do logout (F-03: o servidor não invalida a sessão) |
| Testes | T-09 |
| Campos obrigatórios | `session_ref`, `event_type`, `endpoint`, `status_code`, `username`, `source_ip` |
| Janela / execução | 30 min (vida do cookie) / 1 min |
| Limiar | Requisição bem-sucedida mais de 500 ms depois do `UserLogout` no mesmo `session_ref` (a folga absorve requisições que já estavam em voo no logout) |
| Severidade | High |
| Falsos positivos | Requisições em voo no instante do logout (coberto pela folga); cookie renovado por sliding expiration (muda o `session_ref`, gera falso **negativo**, não positivo) |
| Evidência esperada | T-09: 1 linha, `session_ref` único, `gap_ms=1600` na execução `20261022T210231Z` (logout `-106`, replay `-107`) |
| Validação | `ONLY="T-09"`; conferir que o `session_ref` do resultado é o mesmo do `UserLogout` |

```
application=SecureCorpPortal session_ref=*
| (event_type=UserLogout or (event_type=HttpRequest status_code<400 not endpoint=/\/logout$/))
| lo := if(event_type == "UserLogout", then=@timestamp, else=0)
| rq := if(event_type == "HttpRequest", then=@timestamp, else=0)
| groupBy([session_ref], function=[max(lo, as=logout_at), max(rq, as=last_request_at), count(source_ip, distinct=true, as=sources), collect([username, source_ip], limit=6)])
| logout_at > 0
| gap_ms := last_request_at - logout_at
| gap_ms > 500
```

## DR-12 — Rajada de uploads rejeitados

| | |
|---|---|
| Objetivo | Sondagem do filtro de upload |
| Testes | T-12, T-13, T-15 |
| Campos obrigatórios | `event_type`, `outcome`, `username`, `source_ip`, `properties.details` |
| Janela / execução | 10 min / 1 min |
| Limiar | `rejections >= 3` |
| Severidade | Medium |
| Falsos positivos | Usuário que tenta enviar um formato não suportado várias vezes |
| Evidência esperada | `employee`: T-12 (5) + T-13 (1) + T-15 (1) na mesma janela = 7 |
| Validação | `ONLY="T-12"` já basta (5 rejeições) |

```
application=SecureCorpPortal event_type=DocumentUploaded outcome=failure
| groupBy([username, source_ip], function=[count(as=rejections), collect([properties.details], limit=5)])
| rejections >= 3
```

## DR-13 — Upload com extensão perigosa ou nome com travessia

| | |
|---|---|
| Objetivo | Um único evento já é suspeito: extensão executável/ativa, ou nome enviado com `..`, `/` ou `\` |
| Testes | T-12, T-14 |
| Campos obrigatórios | `event_type`, `properties.details`, `outcome`, `username` |
| Janela / execução | 5 min / 1 min |
| Limiar | Qualquer ocorrência |
| Severidade | Medium (High se `outcome=success`) |
| Falsos positivos | Navegador legado que envia o caminho completo do arquivo |
| Evidência esperada | T-12: 4 de 5 (`.exe`, `.html`, `.svg`, `.docm`; o `MZ` renomeado `.pdf` não casa). T-14: 2 de 3 (`../../x.txt` e `..\x.txt`; o nome Unicode foi corrompido pelo shell) |
| Validação | `ONLY="T-12 T-14"` |

```
application=SecureCorpPortal event_type=DocumentUploaded
| properties.details=/(extens\S{1,2}o '\.(exe|dll|bat|cmd|ps1|sh|js|jsp|php|aspx?|html?|svg|docm|xlsm|jar|war)')|(Nome enviado pelo cliente: '[^']*(\.\.|[\/\\]))/i
| table([@timestamp, username, source_ip, outcome, properties.details], limit=100)
```

## DR-14 — Requisição de upload acima do limite

| | |
|---|---|
| Objetivo | Corpo de upload grande, inclusive o que é rejeitado pelo framework **antes** da auditoria |
| Testes | T-15 |
| Campos obrigatórios | `event_type=HttpRequest`, `http_method`, `endpoint`, `content_length` (campo novo), `username` |
| Janela / execução | 10 min / 1 min |
| Limiar | `big_uploads >= 1` → Low; `>= 3` → Medium |
| Severidade | Low |
| Falsos positivos | Uploads legítimos próximos de 5 MiB |
| Evidência esperada | T-15: 2 eventos (`content_length` 5243304 e 10486186) |
| Validação | `ONLY="T-15"` |

```
application=SecureCorpPortal event_type=HttpRequest http_method=POST endpoint=/^\/(api\/)?documents\/upload$/ content_length>=5242880
| groupBy([username, source_ip], function=[count(as=big_uploads), max(content_length, as=max_bytes)])
```

## DR-15 — Padrões de injection / XSS / traversal na query

| | |
|---|---|
| Objetivo | Classificar `query_string` com padrões de ataque (a query é registrada codificada, com parâmetros sensíveis mascarados) |
| Testes | T-16 |
| Campos obrigatórios | `event_type=HttpRequest`, `query_string`, `endpoint`, `status_code`, `username`, `source_ip` |
| Janela / execução | 5 min / 1 min |
| Limiar | Qualquer ocorrência (Low/Medium por categoria); `>= 5` do mesmo IP → High (ferramenta automática) |
| Severidade | `sqli`, `xss`, `traversal`: Medium; `meta_char`: Low |
| Falsos positivos | `meta_char`: buscas legítimas com aspas ou sobrenomes (O'Brien). `sqli`: texto de documentação técnica |
| Evidência esperada | T-16: 15 de 21 requisições classificadas (`'`→meta_char; `" OR 1=1 --` e `' UNION SELECT NULL--`→sqli; `<script>`→xss; `../../etc/passwd`→traversal). `%` e `_` **não** são classificadas, por design |
| Validação | `ONLY="T-16"` |

```
application=SecureCorpPortal event_type=HttpRequest query_string=*
| case {
    query_string=/(%27|'|%22|")(%20|\+|\s)*(or|and|union|select)\b|union(%20|\+|\s)+select|(%20|\+|\s)or(%20|\+|\s)\d+(=|%3d)\d+|(%20|\+|\s|%27|')(--|%2d%2d)/i | category := "sqli" ;
    query_string=/(%3c|<)(%20|\+|\s|\/)*(script|img|svg|iframe)|on(error|load|mouseover)(=|%3d)|javascript(:|%3a)/i | category := "xss" ;
    query_string=/\.\.(\/|%2f|\\|%5c)|%2e%2e|\/etc\/passwd|%2fetc%2fpasswd|%00/i | category := "traversal" ;
    query_string=/(%27|'|%22|"|%3c|<|%3e|>)/i | category := "meta_char" ;
    * | category := "none"
  }
| category != "none"
| table([@timestamp, username, source_ip, endpoint, status_code, category, query_string], limit=200)
```

## DR-16 — CSRF

**DR-16a — falha de antiforgery (formulários MVC)**

| | |
|---|---|
| Objetivo | POST de formulário sem token ou com token inválido |
| Testes | T-10 |
| Campos obrigatórios | `event_type`, `action`, `resource`, `source_ip`, `user_agent` |
| Janela / execução | 10 min / 1 min |
| Limiar | `failures >= 1` → Medium; `>= 3` → High |
| Severidade | Medium |
| Falsos positivos | Formulário aberto por mais tempo que a vida do token; cookie antiforgery bloqueado |
| Evidência esperada | T-10: 1 evento em `/login` |
| Validação | `ONLY="T-10"` |

```
application=SecureCorpPortal event_type=AccessDenied action="csrf.validation_failed"
| groupBy([source_ip, endpoint], function=[count(as=failures), collect([user_agent], limit=3)])
```

**DR-16b — escrita com origem cruzada**

| | |
|---|---|
| Objetivo | POST/PUT/PATCH/DELETE bem-sucedido cuja origem declarada não é o próprio portal. Útil para a API, que **não** valida antiforgery (F-04) |
| Testes | T-11 |
| Campos obrigatórios | `http_method`, `status_code`, `sec_fetch_site`, `origin`, `referer`, `endpoint`, `username` |
| Janela / execução | 5 min / 1 min |
| Limiar | Qualquer ocorrência |
| Severidade | Medium |
| Falsos positivos | Aplicações legítimas em outra origem do mesmo site no futuro; ajuste a lista de origens. Atrás de túnel SSH a origem é `http://localhost:<porta-local>`: inclua-a |
| Evidência esperada | T-11: 1 evento (`sec_fetch_site=same-site`, `origin=http://localhost:9999`) |
| Validação | `ONLY="T-11"`. **Limitação:** o teste forja os cabeçalhos com curl; falta repetir com um navegador real |

```
application=SecureCorpPortal event_type=HttpRequest username=* status_code<400
| in(field=http_method, values=[POST, PUT, PATCH, DELETE])
| (sec_fetch_site=/^(cross-site|same-site)$/ or (origin=* not origin="http://127.0.0.1:8080"))   // ajuste a(s) origem(ns) legítima(s)
| table([@timestamp, username, source_ip, http_method, endpoint, status_code, origin, sec_fetch_site, referer], limit=100)
```

## DR-17 — Open redirect no login

| | |
|---|---|
| Objetivo | `returnUrl` apontando para fora do portal (link de phishing ou tentativa pós-login) |
| Testes | T-18 |
| Campos obrigatórios | `event_type`, `action`, `query_string`, `endpoint`, `resource`, `username` |
| Janela / execução | 10 min / 1 min |
| Limiar | Qualquer ocorrência |
| Severidade | Medium |
| Falsos positivos | Nenhum esperado: o portal só gera `returnUrl` local |
| Evidência esperada | T-18: 3 eventos (1 `HttpRequest` com `returnUrl=https%3A%2F%2Fevil.test…` e 2 `AccessDenied login.external_return_url_blocked`) |
| Validação | `ONLY="T-18"` |

```
application=SecureCorpPortal
| (event_type=AccessDenied action="login.external_return_url_blocked") or (event_type=HttpRequest endpoint="/login" query_string=/returnurl=(https?(%3a|:)|%2f%2f|\/\/|%5c)/i)
| table([@timestamp, event_type, username, source_ip, resource, query_string], limit=100)
```

## DR-18 — Abuso e enumeração no cadastro

| | |
|---|---|
| Objetivo | Falhas repetidas de cadastro (descoberta de usuário/e-mail existente) ou criação em massa |
| Testes | T-19, T-20 |
| Campos obrigatórios | `event_type`, `action`, `outcome`, `source_ip`, `username`, `properties.details` |
| Janela / execução | 10 min / 1 min |
| Limiar | Lab: `failures >= 2`; prod: `failures >= 3` ou `attempts >= 5` |
| Severidade | Low (Medium se `attempts >= 5`) |
| Falsos positivos | Usuário que tenta nomes comuns já usados |
| Evidência esperada | T-19: `failures=2` (`DuplicateUserName`, `DuplicateEmail`). O envio de `role`/`isAdmin` em T-20 **não** é visível |
| Validação | `ONLY="T-19"` |

```
application=SecureCorpPortal event_type=UserCreated action="user.self_registered"
| failed := if(outcome == "failure", then=1, else=0)
| groupBy([source_ip], function=[count(as=attempts), sum(failed, as=failures), collect([username], limit=10)])
| test(failures >= 2 or attempts >= 5)
```

## DR-19 — Username fora do padrão (senha digitada no campo)

| | |
|---|---|
| Objetivo | Sinalizar tentativa de login com `username` impossível (cadastro só aceita `[A-Za-z0-9._-]`), típico de senha colada no campo errado ou de injeção |
| Testes | T-26 |
| Campos obrigatórios | `event_type`, `username`, `source_ip` |
| Janela / execução | 5 min / 1 min |
| Limiar | Qualquer ocorrência |
| Severidade | Medium |
| Falsos positivos | Usuário digitando e-mail no lugar do usuário |
| Evidência esperada | T-26: 1 evento (`P@ssw0rd!2026`). `senha123` é válido e **não** é detectado |
| Validação | `ONLY="T-26"`. **O resultado da regra contém o possível segredo**: restrinja o acesso e mascare na origem (G-P4) |

```
application=SecureCorpPortal event_type=UserLoginFailed username=/[^A-Za-z0-9._-]/
| table([@timestamp, source_ip, username, properties.details], limit=100)
```

## DR-20 — `X-Request-ID` rejeitado

| | |
|---|---|
| Objetivo | Cliente enviando `X-Request-ID` fora do formato aceito (tentativa de forjar/injetar valor nos logs) |
| Testes | T-25 |
| Campos obrigatórios | `properties.request_id_rejected` (campo novo), `source_ip`, `user_agent` |
| Janela / execução | 10 min / 1 min |
| Limiar | `>= 1` → Low; `>= 5` → Medium |
| Severidade | Low |
| Falsos positivos | Cliente/proxy legítimo que gera IDs em outro formato (ex.: UUID com chaves) |
| Evidência esperada | T-25: 1 evento, `request_id_rejected="bad id; x"` |
| Validação | `ONLY="T-25"` |

```
application=SecureCorpPortal properties.request_id_rejected=*
| groupBy([source_ip, user_agent], function=[count(as=rejected_ids), collect([properties.request_id_rejected], limit=5)])
```

## DR-21 — Status HTTP anômalo e erros em série

**DR-21a — status fora de 100–599**

| | |
|---|---|
| Objetivo | Rota de erro invocada com número arbitrário (F-12) |
| Testes | T-22 |
| Campos obrigatórios | `event_type=HttpRequest`, `status_code`, `endpoint`, `source_ip` |
| Janela / execução | 5 min / 1 min |
| Limiar | Qualquer ocorrência |
| Severidade | Medium |
| Falsos positivos | Nenhum esperado |
| Evidência esperada | T-22: 2 eventos (`status_code` 0 em `/error/0` e 5000 em `/error/5000`) |
| Validação | `ONLY="T-22"` |

```
application=SecureCorpPortal event_type=HttpRequest
| (status_code<100 or status_code>599)
| table([@timestamp, source_ip, endpoint, status_code, severity], limit=100)
```

**DR-21b — erros em série**

| | |
|---|---|
| Objetivo | Entrada que provoca exceções repetidas (possível exploração de falha) |
| Testes | T-16 (nenhum erro esperado), T-22 |
| Campos obrigatórios | `event_type`, `status_code`, `source_ip`, `endpoint` |
| Janela / execução | 5 min / 1 min |
| Limiar | `errors >= 3` (igual ao caso #17 de [detection-use-cases.md](../detection-use-cases.md)) |
| Severidade | High |
| Falsos positivos | Indisponibilidade real do banco |
| Evidência esperada | Nenhum evento nos 28 testes (`ApplicationError` não ocorreu; 5000 conta como `status_code >= 500`, 1 ocorrência) |
| Validação | Não coberta pelos 28 testes; **NOT TESTED** |

```
application=SecureCorpPortal
| (event_type=ApplicationError or (event_type=HttpRequest status_code>=500))
| groupBy([source_ip], function=[count(as=errors), collect([endpoint], limit=10)])
| errors >= 3
```

## DR-22 — Rajadas de 401 e de 404

| | |
|---|---|
| Objetivo | Reconhecimento: sondagem de rotas sem sessão (401) e de caminhos inexistentes (404) |
| Testes | T-24 (e a parte de 404 de T-01/T-02) |
| Campos obrigatórios | `event_type`, `status_code`, `endpoint`, `source_ip` |
| Janela / execução | 2 min / 1 min |
| Limiar | 22a: prod `challenges >= 10`, lab `>= 3`. 22b: prod `not_found >= 30`, lab `>= 15` |
| Severidade | Low (22a) / Medium (22b) |
| Falsos positivos | Sessão expirada em página com várias chamadas AJAX (22a); crawlers legítimos (22b) |
| Evidência esperada | T-24 + T-22: `challenges=4` (22a). T-02: `not_found=17` (22b, lab) |
| Validação | `ONLY="T-22 T-24"` e `ONLY="T-02"` |

```
// 22a — 401/redirect para login em série
application=SecureCorpPortal event_type=AuthenticationRequired
| groupBy([source_ip], function=[count(as=challenges), count(endpoint, distinct=true, as=paths)])
| challenges >= 3        // lab; produção: 10

// 22b — 404 em série
application=SecureCorpPortal event_type=HttpRequest status_code=404
| groupBy([source_ip], function=[count(as=not_found), count(endpoint, distinct=true, as=paths)])
| not_found >= 15        // lab; produção: 30
```

## DR-23 — Consulta à trilha de auditoria

| | |
|---|---|
| Objetivo | Visibilidade de quem leu a auditoria (a própria leitura é auditada) |
| Testes | T-27 |
| Campos obrigatórios | `event_type`, `action`, `username`, `source_ip` |
| Janela / execução | 60 min / 5 min |
| Limiar | Não é alerta por si: use como painel; alerte quando o `source_ip` ou o horário fugir da linha de base |
| Severidade | Informational |
| Falsos positivos | Consulta rotineira por admin |
| Evidência esperada | T-27: 2 eventos (API e página) |
| Validação | `ONLY="T-27"` |

```
application=SecureCorpPortal event_type=AdminAction action="audit_log.viewed"
| table([@timestamp, username, source_ip, endpoint, user_agent], limit=100)
```

## DR-24 — Acesso em massa a documentos

| | |
|---|---|
| Objetivo | Varredura **bem-sucedida** (possível exploração de IDOR ou exfiltração) |
| Testes | T-01 só dispara com varreduras maiores que a executada |
| Campos obrigatórios | `event_type`, `resource`, `username`, `source_ip` |
| Janela / execução | 10 min / 1 min |
| Limiar | `distinct_docs >= 10` (igual ao caso #8 de [detection-use-cases.md](../detection-use-cases.md)) |
| Severidade | Medium |
| Falsos positivos | Analista revisando muitos documentos |
| Evidência esperada | T-01 como executado: `distinct_docs=6`, **não dispara** (esperado) |
| Validação | Estender a varredura de T-01 além do id 15 em um seed maior; **NOT TESTED** |

```
application=SecureCorpPortal event_type=DocumentAccessed
| groupBy([username, source_ip], function=[count(resource, distinct=true, as=distinct_docs), count(as=reads)])
| distinct_docs >= 10
```

## DR-25 — Visão de correlação do tráfego de teste (auxiliar)

Não é detecção: agrupa todos os eventos de cada requisição de teste pelo `request_id` (`PT-<teste>-<RUN>-<seq>`),
para conferir a cadeia **requisição → resposta → evento → log ingerido**.

```
application=SecureCorpPortal request_id=/^PT-(?<test>[A-Z]\d{2})-(?<run>[0-9]{8}T[0-9]{6}Z)-(?<seq>\d{3})$/
| groupBy([test, run, request_id], function=[collect([event_type, action, outcome, status_code], limit=10), min(@timestamp, as=first_seen)], limit=max)
| sort(request_id, order=asc)
```

Resultado esperado para a execução `20261022T210231Z`: 193 requisições (`requests.tsv`), cada uma com ao menos um `HttpRequest`.
