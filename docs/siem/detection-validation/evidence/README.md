# Evidências

Uma pasta por execução do `tools/run-pentest-cases.sh`, nomeada pelo `RUN_ID` (data/hora UTC).

| Arquivo | Origem | Conteúdo |
|---|---|---|
| `<teste>.log` | executor | Requisições do teste: comando (senhas mascaradas), status, `Location`, 300 primeiros bytes da resposta, notas |
| `requests.tsv` | executor | `teste, request_id, método, caminho, status` |
| `expect.tsv` | executor | Eventos que devem existir no log de cada requisição |
| `local-verification.tsv` | `verify-local-logs.py` | Uma linha por expectativa: `OK`/`MISSING` e os eventos observados |
| `local-summary.tsv` | `verify-local-logs.py` | `LOCAL-PASS`/`LOCAL-FAIL` por teste |
| `local-events/<teste>.jsonl` | `verify-local-logs.py` | As linhas do log do portal que comprovam os eventos (cópia literal) |
| `siem/` | **manual** | Capturas/CSV da busca no NG-SIEM (ingestão) e do alerta (id, horário, regra). **Não existe na execução de referência: etapa de SIEM não executada** |

## Execução de referência: `20261022T210231Z`

- Alvo: portal em Docker local, banco novo com seed, porta 18080 (`source_ip` = gateway da bridge).
- 193 requisições, 404 expectativas, 404 confirmadas nos logs locais.
- Resultado da validação **local**; não comprova ingestão nem alertas no Falcon NG-SIEM.
- O texto `relat�rio` em T-14 é artefato de codificação do shell do Windows ao enviar o nome do arquivo.
- Contém nomes de usuário digitados de propósito (T-26: `P@ssw0rd!2026`); material de laboratório.

Para registrar uma nova execução, mantenha a pasta anterior (comparação) e atualize `../results/validation-results.csv` com o novo `local_run_id`.
