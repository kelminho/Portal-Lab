using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using Serilog.Events;
using Serilog.Formatting;
using Serilog.Parsing;

namespace SecureCorpPortal.Logging;

/// <summary>
/// Formatter Serilog que grava UM objeto JSON por linha (formato "JSON Lines"),
/// com nomes de campo estáveis em snake_case — fácil de ingerir em qualquer SIEM.
///
/// Exemplo de saída (quebrado em linhas aqui só para leitura):
/// {"timestamp":"2026-01-01T12:00:00.000Z","level":"Warning","severity":"medium",
///  "message":"Audit UserLoginFailed: auth.login [failure]", "event_type":"UserLoginFailed",
///  "event_category":"audit","request_id":"...","source_ip":"172.18.0.1","username":"employee", ...}
///
/// Campos conhecidos vão para o nível superior; os demais ficam em "properties".
/// Propriedades com nomes sensíveis (password, token...) são mascaradas.
/// </summary>
public sealed class SiemJsonFormatter : ITextFormatter
{
    /// <summary>Campos promovidos ao nível superior, nesta ordem.</summary>
    private static readonly string[] TopLevelFields =
    [
        LogFields.EventType,
        LogFields.EventCategory,
        LogFields.Action,
        LogFields.Outcome,
        LogFields.RequestId,
        LogFields.SourceIp,
        LogFields.SourcePort,
        LogFields.UserId,
        LogFields.Username,
        LogFields.HttpMethod,
        LogFields.Endpoint,
        LogFields.QueryString,
        LogFields.StatusCode,
        LogFields.DurationMs,
        LogFields.UserAgent,
        LogFields.SessionRef,
        LogFields.Origin,
        LogFields.Referer,
        LogFields.SecFetchSite,
        LogFields.ContentLength,
        LogFields.Resource
    ];

    private static readonly HashSet<string> TopLevelSet = new(TopLevelFields, StringComparer.Ordinal)
    {
        LogFields.Severity,
        "SourceContext"
    };

    /// <summary>Propriedades adicionadas pelo ASP.NET Core que são redundantes para o SIEM.</summary>
    private static readonly HashSet<string> IgnoredProperties = new(StringComparer.Ordinal)
    {
        "RequestId", "RequestPath", "ConnectionId", "EventId", "ActionId", "{OriginalFormat}"
    };

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        // Mantém acentos legíveis ("não" em vez de "não").
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
    };

    private readonly string _application;
    private readonly string? _environment;
    private readonly string _host;

    public SiemJsonFormatter(string application = "SecureCorpPortal", string? environment = null, string? host = null)
    {
        _application = application;
        _environment = environment;
        _host = host ?? Environment.MachineName;
    }

    public void Format(LogEvent logEvent, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        ArgumentNullException.ThrowIfNull(output);

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
        {
            writer.WriteStartObject();

            writer.WriteString(LogFields.Timestamp,
                logEvent.Timestamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
            writer.WriteString("level", logEvent.Level.ToString());
            writer.WriteString(LogFields.Severity, ResolveSeverity(logEvent));
            writer.WriteString("message", RenderMessage(logEvent));
            writer.WriteString("message_template", logEvent.MessageTemplate.Text);
            writer.WriteString("application", _application);
            if (_environment is not null)
            {
                writer.WriteString("environment", _environment);
            }

            writer.WriteString("host", _host);

            if (logEvent.TraceId is { } traceId)
            {
                writer.WriteString("trace_id", traceId.ToHexString());
            }

            if (logEvent.Properties.TryGetValue("SourceContext", out var sourceContext) &&
                sourceContext is ScalarValue { Value: string source })
            {
                writer.WriteString("source_context", source);
            }

            foreach (var field in TopLevelFields)
            {
                if (logEvent.Properties.TryGetValue(field, out var value) && !IsNull(value))
                {
                    writer.WritePropertyName(field);
                    WriteValue(writer, field, value);
                }
            }

            var extras = logEvent.Properties
                .Where(p => !TopLevelSet.Contains(p.Key) && !IgnoredProperties.Contains(p.Key) && !IsNull(p.Value))
                .ToList();

            if (extras.Count > 0)
            {
                writer.WriteStartObject("properties");
                foreach (var (name, value) in extras)
                {
                    writer.WritePropertyName(name);
                    WriteValue(writer, name, value);
                }

                writer.WriteEndObject();
            }

            if (logEvent.Exception is { } exception)
            {
                writer.WriteStartObject("exception");
                writer.WriteString("type", exception.GetType().FullName);
                writer.WriteString("message", exception.Message);
                writer.WriteString("stack_trace", exception.ToString());
                writer.WriteEndObject();
            }

            writer.WriteEndObject();
        }

        output.Write(Encoding.UTF8.GetString(buffer.WrittenSpan));
        output.Write('\n');
    }

    /// <summary>
    /// Usa a propriedade "severity" quando o evento a define (ex.: auditoria);
    /// caso contrário, deriva do nível do log.
    /// </summary>
    private static string ResolveSeverity(LogEvent logEvent)
    {
        if (logEvent.Properties.TryGetValue(LogFields.Severity, out var value) &&
            value is ScalarValue { Value: string severity } &&
            !string.IsNullOrWhiteSpace(severity))
        {
            return severity.ToLowerInvariant();
        }

        return logEvent.Level switch
        {
            LogEventLevel.Fatal => "critical",
            LogEventLevel.Error => "high",
            LogEventLevel.Warning => "medium",
            _ => "info"
        };
    }

    /// <summary>
    /// Renderiza a mensagem sem aspas em strings e mascarando propriedades sensíveis.
    /// </summary>
    private static string RenderMessage(LogEvent logEvent)
    {
        var builder = new StringBuilder();
        foreach (var token in logEvent.MessageTemplate.Tokens)
        {
            switch (token)
            {
                case TextToken text:
                    builder.Append(text.Text);
                    break;

                case PropertyToken property when SensitiveData.IsSensitiveKey(property.PropertyName):
                    builder.Append(SensitiveData.Mask);
                    break;

                case PropertyToken property when logEvent.Properties.TryGetValue(property.PropertyName, out var value):
                    if (value is ScalarValue { Value: string stringValue })
                    {
                        builder.Append(stringValue);
                    }
                    else
                    {
                        // Estruturas/listas são renderizadas a partir de uma cópia já mascarada.
                        using var writer = new StringWriter(CultureInfo.InvariantCulture);
                        Redact(value).Render(writer, property.Format, CultureInfo.InvariantCulture);
                        builder.Append(writer);
                    }

                    break;

                case PropertyToken property:
                    builder.Append('{').Append(property.PropertyName).Append('}');
                    break;
            }
        }

        return builder.ToString();
    }

    private static bool IsNull(LogEventPropertyValue value) => value is ScalarValue { Value: null };

    /// <summary>Cria uma cópia do valor com os campos sensíveis (em qualquer nível) mascarados.</summary>
    private static LogEventPropertyValue Redact(LogEventPropertyValue value) => value switch
    {
        StructureValue structure => new StructureValue(
            structure.Properties.Select(p => new LogEventProperty(p.Name,
                SensitiveData.IsSensitiveKey(p.Name) ? new ScalarValue(SensitiveData.Mask) : Redact(p.Value))),
            structure.TypeTag),

        SequenceValue sequence => new SequenceValue(sequence.Elements.Select(Redact)),

        DictionaryValue dictionary => new DictionaryValue(dictionary.Elements.Select(kv =>
            new KeyValuePair<ScalarValue, LogEventPropertyValue>(kv.Key,
                SensitiveData.IsSensitiveKey(Convert.ToString(kv.Key.Value, CultureInfo.InvariantCulture))
                    ? new ScalarValue(SensitiveData.Mask)
                    : Redact(kv.Value)))),

        _ => value
    };

    private static void WriteValue(Utf8JsonWriter writer, string? name, LogEventPropertyValue value)
    {
        if (SensitiveData.IsSensitiveKey(name))
        {
            writer.WriteStringValue(SensitiveData.Mask);
            return;
        }

        switch (value)
        {
            case ScalarValue scalar:
                WriteScalar(writer, scalar.Value);
                break;

            case SequenceValue sequence:
                writer.WriteStartArray();
                foreach (var element in sequence.Elements)
                {
                    WriteValue(writer, null, element);
                }

                writer.WriteEndArray();
                break;

            case StructureValue structure:
                writer.WriteStartObject();
                if (structure.TypeTag is not null)
                {
                    writer.WriteString("_type", structure.TypeTag);
                }

                foreach (var property in structure.Properties)
                {
                    writer.WritePropertyName(property.Name);
                    WriteValue(writer, property.Name, property.Value);
                }

                writer.WriteEndObject();
                break;

            case DictionaryValue dictionary:
                writer.WriteStartObject();
                foreach (var (key, element) in dictionary.Elements)
                {
                    var keyText = Convert.ToString(key.Value, CultureInfo.InvariantCulture) ?? "null";
                    writer.WritePropertyName(keyText);
                    WriteValue(writer, keyText, element);
                }

                writer.WriteEndObject();
                break;

            default:
                writer.WriteStringValue(value.ToString());
                break;
        }
    }

    private static void WriteScalar(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                break;
            case string s:
                writer.WriteStringValue(s);
                break;
            case bool b:
                writer.WriteBooleanValue(b);
                break;
            case int i:
                writer.WriteNumberValue(i);
                break;
            case long l:
                writer.WriteNumberValue(l);
                break;
            case short sh:
                writer.WriteNumberValue(sh);
                break;
            case byte by:
                writer.WriteNumberValue(by);
                break;
            case uint ui:
                writer.WriteNumberValue(ui);
                break;
            case ulong ul:
                writer.WriteNumberValue(ul);
                break;
            case decimal m:
                writer.WriteNumberValue(m);
                break;
            case double d when double.IsFinite(d):
                writer.WriteNumberValue(d);
                break;
            case float f when float.IsFinite(f):
                writer.WriteNumberValue(f);
                break;
            case DateTime dt:
                writer.WriteStringValue(dt.ToString("O", CultureInfo.InvariantCulture));
                break;
            case DateTimeOffset dto:
                writer.WriteStringValue(dto.ToString("O", CultureInfo.InvariantCulture));
                break;
            case TimeSpan ts:
                writer.WriteStringValue(ts.ToString("c", CultureInfo.InvariantCulture));
                break;
            default:
                writer.WriteStringValue(Convert.ToString(value, CultureInfo.InvariantCulture));
                break;
        }
    }
}
