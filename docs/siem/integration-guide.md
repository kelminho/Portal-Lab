# Guia de integração com o SIEM

## 1. IP de origem

O `source_ip` vem do IP da conexão TCP. Para que ele seja o IP real do atacante/cliente:

1. **Publique a porta no IP da rede isolada do lab**, não só em `127.0.0.1`. No `.env`:
   ```
   BIND_IP=192.168.56.10      # IP da interface da VM na rede do lab
   ```
   Em Linux, o Docker normalmente preserva o IP de origem de clientes externos nesse modo.
   Conexões feitas de dentro da própria VM (`curl localhost`) aparecem com o IP do gateway da
   bridge (ex.: `172.19.0.1`); isso é esperado.
2. **Valide** gerando uma falha de login a partir da VM atacante e conferindo `source_ip` em
   `logs/security-*.json`.
3. **Atrás de proxy reverso**, habilite o encaminhamento de headers e confie **só** no proxy:
   ```
   ForwardedHeaders__Enabled=true
   ForwardedHeaders__KnownProxies__0=172.19.0.1
   # ou: ForwardedHeaders__KnownNetworks__0=172.16.0.0/12
   ```
   Sem a lista de confiança, o portal ignora `X-Forwarded-For` (evita que o atacante forje o IP).
   Essas variáveis precisam ser repassadas ao serviço `web` no `docker-compose.yml`.

Docker Desktop (Windows/macOS) mascara o IP de origem; use uma VM Linux para o laboratório.

## 2. Coleta dos arquivos

Os logs ficam em `logs/` na raiz do projeto (volume `./logs:/app/logs`). O container grava como
UID 1654:

```bash
mkdir -p logs && sudo chown -R 1654:1654 logs
```

O agente do SIEM precisa de leitura nessa pasta.

| Arquivo | Uso |
|---|---|
| `logs/security-*.json` | Alertas de autenticação, autorização e auditoria |
| `logs/securecorp-*.json` | Tráfego (`HttpRequest`), erros e demais eventos |

Configuração comum a qualquer agente (Wazuh, Elastic Agent/Filebeat, Splunk UF, etc.):

- tipo de entrada: arquivo, **JSON por linha** (decodificar como JSON);
- campo de tempo: `timestamp` (ISO 8601, UTC);
- `security-*` é subconjunto de `securecorp-*`, então eventos de auditoria aparecem nos dois.
  Para evitar alertas duplicados, use `security-*` para as detecções de auditoria e
  `securecorp-*` apenas para as de tráfego (`event_type = HttpRequest`) e erros.

Alternativa: `docker compose logs -f web` (saída JSON, `AppLogging__ConsoleFormat=json`).

## 3. Validação rápida

```bash
# a partir da VM atacante
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -H "Content-Type: application/json" \
    -d '{"userName":"employee","password":"errada"}' http://IP_DO_PORTAL:8080/api/auth/login
done
curl -s -o /dev/null "http://IP_DO_PORTAL:8080/search?q=%27%20OR%201%3D1--"

# no portal
tail -n 8 logs/security-*.json
grep query_string logs/securecorp-*.json | tail -n 2
```

Esperado: `UserLoginFailed` repetidos, depois `UserLockedOut`, e um `HttpRequest` com `query_string`.
Atenção: o `employee` ficará bloqueado por 15 min; desbloqueie em `/admin/users` como admin.
