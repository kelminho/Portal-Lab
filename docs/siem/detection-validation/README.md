# Validação de detecção — pentest × Falcon NG-SIEM (purple team)

Liga os 28 testes de [`security-test-instructions.md`](../../architecture/security-test-instructions.md) (T-01…T-28)
aos eventos que o portal grava e às regras CQL que devem detectá-los. Permite: executar um teste, achar seus eventos pelo
`X-Request-ID`, consultá-los no SIEM e registrar se a detecção funcionou.

> **Alvo único: laboratório local/isolado e autorizado.** Nada aqui foi executado no Falcon NG-SIEM:
> a validação feita é **local** (logs do portal). Ingestão e disparo de regras estão `NOT TESTED`.

## Onde está cada coisa

| Arquivo | O que contém |
|---|---|
| [`test-matrix.md`](test-matrix.md) | Matriz dos 28 testes: categoria, endpoint, MITRE, evento esperado, campos, regras, severidade, detectabilidade, lacunas, validação e os estados (tentativa/bloqueada/possível exploração/confirmada/falha) |
| [`detection-rules.md`](detection-rules.md) | 25 regras CQL (DR-01…DR-25) com janela, limiar, falsos positivos, evidência esperada e procedimento de validação |
| [`execution-runbook.md`](execution-runbook.md) | Como executar, correlacionar (`X-Request-ID`), ingerir, validar a regra, tratar SSH port forwarding e registrar o resultado |
| [`telemetry-gaps.md`](telemetry-gaps.md) | Melhorias de logging **implementadas** (G-01…G-08) e lacunas **pendentes** (G-P1…G-P12) |
| [`results/validation-results.csv`](results/validation-results.csv) | Um status por teste, separando local, ingestão e alerta |
| [`evidence/`](evidence/README.md) | Requisição/resposta e eventos por execução. Referência: `20261022T210231Z` |
| [`tools/run-pentest-cases.sh`](tools/run-pentest-cases.sh) | Executa os 28 testes (curl), marca cada requisição com `X-Request-ID`, grava evidência |
| [`tools/verify-local-logs.py`](tools/verify-local-logs.py) | Confere nos logs locais se cada requisição gerou os eventos esperados |

Documentação reaproveitada, não duplicada: [`log-schema.md`](../log-schema.md), [`event-catalog.md`](../event-catalog.md) (ambos atualizados com os campos/eventos novos),
[`detection-use-cases.md`](../detection-use-cases.md) (casos genéricos; as regras daqui os detalham para os testes) e [`integration-guide.md`](../integration-guide.md) (coleta e IP de origem).

## Início rápido

```bash
cd docs/siem/detection-validation/tools
BASE_URL=http://127.0.0.1:8080 ./run-pentest-cases.sh          # ou ONLY="T-07 T-09"
python3 -I verify-local-logs.py --evidence-dir ../evidence/<RUN_ID> --log-dir ../../../../logs
```

Depois, no SIEM: consulta DR-25 pelo `RUN_ID`, regras DR-xx do teste, e registro em `results/validation-results.csv`
([runbook §5 a §7](execution-runbook.md)).

## Critérios de status

| Status | Significado |
|---|---|
| `PASS` | Evento gerado, **ingerido** e detecção funcionando como esperado (evidência das três etapas) |
| `PARTIAL` | Evento identificado, mas detecção incompleta |
| `FAIL` | Teste executado e a detecção esperada não ocorreu |
| `NOT SUPPORTED` | Telemetria insuficiente para detectar |
| `NOT TESTED` | Validação ainda não executada |

Na etapa local o CSV usa `LOCAL-PASS` / `LOCAL-PARTIAL` (parte do ataque sem telemetria) / `NOT SUPPORTED`.
O `final_status` só pode ser `PASS` com as três etapas comprovadas; hoje nenhuma foi.

## Resultado atual (execução local `20261022T210231Z`)

Alvo: Docker local (porta 18080), banco novo com seed. 193 requisições, 404 expectativas de log, **404 confirmadas**.
Suíte xUnit no container .NET 8: **204 testes, 204 aprovados** (antes: 197; 7 novos).

| Detectabilidade (telemetria local) | Testes |
|---|---|
| **Total** (18) | T-01, 02, 03, 04, 06, 07, 08, 09, 10, 12, 14, 15, 18, 19, 24, 25, 27, 28 |
| **Parcial** (8) | T-05, 11, 13, 16, 20, 21, 22, 26 |
| **Não Detectável** (2) | T-17 (corpo não registrado), T-23 (teste passivo) |

No CSV: `LOCAL-PASS` = Total (18), `LOCAL-PARTIAL` = Parcial (8), `NOT SUPPORTED` = Não Detectável (2).

| Etapa | Resultado |
|---|---|
| Eventos presentes no log local | 26 de 28 testes com telemetria; T-17 e T-23 sem |
| Regras CQL escritas | 25 (DR-01…DR-25), **0 executadas** em NG-SIEM |
| Ingestão no NG-SIEM confirmada | 0 de 28 (`NOT TESTED`) |
| Alertas do NG-SIEM confirmados | 0 de 28 (`NOT TESTED`) |

**O que não é possível afirmar ainda:** que qualquer ataque seja detectado no SIEM. Só se sabe que o portal grava os eventos
necessários para 26 dos 28 testes e quais dois não têm como ser detectados com a telemetria atual.

## Pendências

1. Ingerir os logs no tenant, validar o parser e as 25 consultas CQL (sintaxe não executada) e registrar `siem_ingest_status`/`siem_alert_status`.
2. Casos não exercitados pelos 28 testes: DR-05 (sucesso após falhas), DR-09 (`RoleChanged` por não-admin), DR-21b e DR-24 (volume maior).
3. T-11 em navegador real; T-25 com CR/LF (curl não envia).
4. Lacunas G-P1 a G-P12 de [`telemetry-gaps.md`](telemetry-gaps.md); G-P8 (logout não invalida) e G-P9 (sem rate limit) são correções de código que dependem de autorização.
