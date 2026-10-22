# Documentação para SIEM / SOC

Material para quem vai ingerir os logs do SecureCorp Portal e criar detecções.

| Documento | Conteúdo |
|---|---|
| [log-schema.md](log-schema.md) | Campos do JSON, tipos e arquivos gerados |
| [event-catalog.md](event-catalog.md) | Cada `event_type`, severidade padrão e quando é emitido |
| [detection-use-cases.md](detection-use-cases.md) | Detecções sugeridas, com campos e limiares |
| [integration-guide.md](integration-guide.md) | Como coletar os arquivos e validar o IP de origem |

Pontos de atenção antes de criar alertas:

1. **`source_ip` só é confiável se o portal for alcançado pelo IP real do cliente.** Veja
   [integration-guide.md](integration-guide.md#1-ip-de-origem).
2. **A `query_string` é registrada** (parâmetros sensíveis mascarados) e é a fonte para detectar
   SQLi/XSS/path traversal em `/search`, `/documents` e `/api/documents`.
3. Use `security-*.json` para alertas de autenticação/autorização e `securecorp-*.json`
   (`event_type = HttpRequest`) para padrões de tráfego e varredura.
