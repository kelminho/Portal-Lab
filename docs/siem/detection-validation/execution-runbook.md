# Runbook — executar um teste e provar que o SIEM o detectou

Fluxo completo, do pentest ao alerta:

```
curl (X-Request-ID: PT-T07-<RUN>-091) ──► resposta HTTP (401, mesmo X-Request-ID)
        │                                          │
        ▼                                          ▼
 portal grava 2 linhas JSON com o mesmo request_id:
   • evento de auditoria  (UserLoginFailed / UserLockedOut …)      → security-*.json e securecorp-*.json
   • HttpRequest          (status_code, duration_ms, query_string…) → securecorp-*.json
        │
        ▼
 coletor de arquivos ──► Falcon NG-SIEM (parser JSON) ──► consulta DR-25 por request_id ──► regra CQL (DR-xx) ──► alerta
   etapa 1: validação LOCAL (verify-local-logs.py)        etapa 2: ingestão        etapa 3: disparo da regra
```

As três etapas são registradas **separadamente** em [`results/validation-results.csv`](results/validation-results.csv).
Só se marca `PASS` com evidência das três.

## 1. Pré-requisitos

- Alvo: **somente** o laboratório (`127.0.0.1` ou rede isolada). Contas de seed públicas ([README raiz](../../../README.md#9-usuários-de-teste)).
- `bash` + `curl` + `python3` (o executor e o verificador). No Windows, Git Bash.
- Portal no ar (`docker compose up -d --build`). Se a porta 8080 estiver ocupada: `WEB_PORT=18080 docker compose up -d`.
- Para a etapa 2: acesso de escrita ao tenant (conector/parser) e de leitura à busca; **sem alterar regras existentes**.

## 2. Convenções de correlação

| Item | Valor | Onde aparece |
|---|---|---|
| `X-Request-ID` | `PT-<teste>-<RUN_ID>-<seq>` (`PT-T07-20261022T210231Z-091`). Formato aceito pelo portal: `^[A-Za-z0-9._-]{8,64}$` | cabeçalho da resposta e campo `request_id` de **todas** as linhas da requisição |
| `User-Agent` | `PentestLab/<RUN_ID>` | `user_agent` |
| Contas de teste criadas | `pt.<função>.<RUN_ID>` (ex.: `pt.lock.<RUN_ID>`) | `username`; removidas no fim pelo admin (`S99`) |
| Preparação / limpeza | testes `S00` (login dos 4 papéis, upload `Restricted`) e `S99` (exclusões) | `request_id` `PT-S00-…`, `PT-S99-…` |

`RUN_ID` é a data/hora UTC do início (`20261022T210231Z`). Use sempre o mesmo `RUN_ID` na busca do SIEM.
Um `X-Request-ID` inválido é substituído por um GUID e o valor enviado vai para `properties.request_id_rejected`.

## 3. Executar

```bash
cd docs/siem/detection-validation/tools

# todos os testes (≈ 190 requisições, alguns minutos)
BASE_URL=http://127.0.0.1:8080 ./run-pentest-cases.sh

# só alguns (a preparação S00 e a limpeza S99 sempre rodam)
ONLY="T-04 T-07" BASE_URL=http://127.0.0.1:8080 ./run-pentest-cases.sh
```

Saída em `evidence/<RUN_ID>/`:

| Arquivo | Conteúdo |
|---|---|
| `<teste>.log` | cada requisição: comando (senhas mascaradas), status, `Location`, 300 primeiros bytes do corpo, notas |
| `requests.tsv` | `teste, request_id, método, caminho, status` |
| `expect.tsv` | o que **deve** existir no log para cada requisição (ver o cabeçalho de `verify-local-logs.py`) |

O executor não é destrutivo: cria contas/documentos próprios, usa 1 senha errada por conta de seed (T-08), e remove o que criou.
A conta `pt.lock.<RUN_ID>` fica bloqueada por 15 min; as de seed não são bloqueadas.

## 4. Validação local (etapa 1)

```bash
python3 -I verify-local-logs.py --evidence-dir ../evidence/<RUN_ID> --log-dir ../../../../logs
```

Gera `local-verification.tsv` (uma linha por expectativa, `OK`/`MISSING` e os eventos observados), `local-summary.tsv`
(`LOCAL-PASS`/`LOCAL-FAIL` por teste) e `local-events/<teste>.jsonl` (as linhas de log que servem de evidência).
`LOCAL-PASS` diz apenas que os eventos **esperados pelo executor** existem; a avaliação de lacunas (status `PARTIAL`/`NOT SUPPORTED`) está na [matriz](test-matrix.md).

Reset entre rodadas (apaga banco e uploads; os logs de `logs/` não são apagados):

```bash
docker compose down -v && docker compose up -d
```

Execução de referência deste repositório: [`evidence/20261022T210231Z/`](evidence/20261022T210231Z/) — 193 requisições, 404 expectativas, 404 confirmadas.
Foi feita contra o Docker local na porta 18080 (`source_ip` = gateway da bridge, `172.21.0.1`).

## 5. Ingestão no Falcon NG-SIEM (etapa 2)

Este repositório **não contém** parser nem configuração do coletor (verificado). O que existe é o formato dos arquivos
([`log-schema.md`](../log-schema.md)) e o guia de coleta ([`integration-guide.md`](../integration-guide.md)).

1. Configure um coletor de arquivos (ex.: Falcon LogScale Collector) lendo `logs/securecorp-*.json` (**e** `security-*.json`, ver deduplicação em [detection-rules.md](detection-rules.md#convenções)), uma linha = um evento JSON.
2. Parser: esboço **não validado**, para testar no *Test parser* do tenant:

   ```
   parseJson()
   | parseTimestamp(format="yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", field=timestamp, timezone="UTC")
   ```
   Os campos aninhados devem ficar como `properties.details` e `properties.request_id_rejected`, que é o que as regras usam.
3. Confirme a ingestão com a consulta DR-25 (busca por `request_id`) no intervalo do teste. Critério: o número de `request_id`
   distintos com prefixo `PT-<teste>-<RUN_ID>` é igual ao de `requests.tsv`, e cada um tem o evento esperado de `expect.tsv`.
4. Guarde a captura/CSV da busca em `evidence/<RUN_ID>/siem/<teste>-ingest.*` e preencha `siem_ingest_status` no CSV.

## 6. SSH port forwarding

Se o teste passa por um túnel (`ssh -L 8080:127.0.0.1:8080 usuario@host-do-lab`), o portal vê a conexão que o **sshd do host do
laboratório** abre localmente: `source_ip` será `127.0.0.1` ou o gateway da bridge do Docker (ex.: `172.21.0.1`), nunca o IP do
atacante. O IP real só existe no log do sshd (`Accepted … from <ip> port <p>`). Opções, da melhor para a pior:

1. **Evitar o túnel.** Publicar a porta no IP da rede isolada (`BIND_IP`) e testar direto da VM atacante ([integration-guide §1](../integration-guide.md#1-ip-de-origem)).
2. **Identificar o tráfego de teste sem depender do IP.** O executor já marca `request_id` (`PT-…`) e `user_agent` (`PentestLab/<RUN_ID>`), que
   estão em todas as linhas. Ambos são controlados por quem testa; servem para correlação em laboratório, não como prova de origem.
3. **Atribuir ao túnel pela porta de origem.** O portal registra `source_port` (porta efêmera da conexão que o sshd abriu). Se o host do
   laboratório tem telemetria de rede (por exemplo, eventos de conexão do sensor Falcon, com processo e portas), o par
   `(source_port, horário)` liga a requisição ao processo `sshd` da sessão, e este à sessão SSH (usuário e IP de origem no log de
   autenticação). **Hipótese, não validada**: depende de quais eventos de rede o tenant ingere.
4. **Não confiar em `X-Forwarded-For`.** `ForwardedHeaders` fica desligado por padrão (`appsettings.json`); habilitá-lo atrás de túnel
   permitiria ao cliente forjar o IP.

Efeitos nas regras: agrupe por `source_ip` **e** `user_agent` (DR-03 já faz isso); inclua `http://localhost:<porta-local>` na lista de
origens legítimas de DR-16b; trate `source_ip` em `127.0.0.1`/bridge como "origem local ou túnel" (a visão de todos os atacantes colapsa em um IP).

## 7. Registrar o resultado

[`results/validation-results.csv`](results/validation-results.csv), uma linha por teste:

| Coluna | Valores |
|---|---|
| `local_status` | `LOCAL-PASS` (eventos esperados presentes), `LOCAL-PARTIAL` (parte do ataque sem telemetria), `NOT SUPPORTED` (sem telemetria), `NOT TESTED` |
| `siem_ingest_status` | `PASS` (eventos do `RUN_ID` encontrados pelo `request_id`), `FAIL`, `NOT TESTED` |
| `siem_alert_status` | `PASS` (alerta disparou com os eventos esperados), `PARTIAL`, `FAIL` (executou e não disparou), `NOT SUPPORTED`, `NOT TESTED` |
| `final_status` | `PASS` só se as três colunas anteriores forem `PASS`/`LOCAL-PASS`; `PARTIAL`, `FAIL`, `NOT SUPPORTED` ou `NOT TESTED` nos demais casos |
| `evidence` | pasta de evidência e, quando houver, `siem/<arquivo>` com a captura do alerta (id, horário, regra) |

Modelo de registro por teste (herdado de [`security-test-instructions.md` §12](../../architecture/security-test-instructions.md#12-critérios-de-aceite-e-registro-de-resultados), com as colunas de SIEM):

```text
ID do teste / RUN_ID:
Data/hora UTC · Executor · Papel/usuário:
Requisição(ões) (request_id):
Resposta (status + trecho):
Eventos no log local (arquivo local-events/<teste>.jsonl):
Ingestão no SIEM (consulta DR-25, nº de eventos, captura):
Regra DR-xx: disparou? (id do alerta, horário, severidade):
Resultado:  PASS | PARTIAL | FAIL | NOT SUPPORTED | NOT TESTED
Observações / lacuna (G-xx):
```

## 8. Cuidados

- **Só laboratório.** Nada aqui deve apontar para alvo externo; o executor não faz varredura nem carga.
- Docker Desktop (Windows/macOS) mascara o IP de origem; a validação de `source_ip` real exige VM Linux ([integration-guide](../integration-guide.md)).
- Os logs de teste contêm usernames digitados (T-26 grava `P@ssw0rd!2026` como `username`); trate `evidence/` como material de laboratório e não envie a ambientes compartilhados sem revisar.
- T-11 usa cabeçalhos forjados com curl. Repita no navegador (página local em outra porta) antes de afirmar algo sobre CSRF real.
- O executor depende de `cygpath` para caminhos do curl no Git Bash; em Linux/macOS ele é ignorado.
