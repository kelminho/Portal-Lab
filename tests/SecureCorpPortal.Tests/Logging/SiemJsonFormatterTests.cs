using System.Text.Json;
using SecureCorpPortal.Logging;
using Serilog.Events;
using Serilog.Parsing;

namespace SecureCorpPortal.Tests.Logging;

/// <summary>Testes unitários do formato JSON enviado aos arquivos de log / SIEM.</summary>
public class SiemJsonFormatterTests
{
    private static readonly MessageTemplateParser Parser = new();

    [Fact]
    public void Format_WritesSingleLineJsonWithStandardFields()
    {
        var logEvent = CreateEvent(LogEventLevel.Information, "Usuário {username} acessou {endpoint}",
            ("username", new ScalarValue("alice")),
            ("endpoint", new ScalarValue("/dashboard")),
            ("request_id", new ScalarValue("abc123def456")),
            ("event_type", new ScalarValue("HttpRequest")),
            ("status_code", new ScalarValue(200)));

        var output = Format(logEvent);

        Assert.EndsWith("\n", output);
        Assert.Single(output.TrimEnd('\n').Split('\n'));

        using var json = JsonDocument.Parse(output);
        var root = json.RootElement;
        Assert.Equal("Information", root.GetProperty("level").GetString());
        Assert.Equal("info", root.GetProperty("severity").GetString());
        Assert.Equal("Usuário alice acessou /dashboard", root.GetProperty("message").GetString());
        Assert.Equal("alice", root.GetProperty("username").GetString());
        Assert.Equal("abc123def456", root.GetProperty("request_id").GetString());
        Assert.Equal("HttpRequest", root.GetProperty("event_type").GetString());
        Assert.Equal(200, root.GetProperty("status_code").GetInt32());
        Assert.Equal("SecureCorpPortal", root.GetProperty("application").GetString());
        Assert.Equal("Testing", root.GetProperty("environment").GetString());
        Assert.EndsWith("Z", root.GetProperty("timestamp").GetString());
    }

    [Theory]
    [InlineData(LogEventLevel.Debug, "info")]
    [InlineData(LogEventLevel.Information, "info")]
    [InlineData(LogEventLevel.Warning, "medium")]
    [InlineData(LogEventLevel.Error, "high")]
    [InlineData(LogEventLevel.Fatal, "critical")]
    public void Format_DerivesSeverityFromLevel(LogEventLevel level, string expected)
    {
        var output = Format(CreateEvent(level, "mensagem"));

        using var json = JsonDocument.Parse(output);
        Assert.Equal(expected, json.RootElement.GetProperty("severity").GetString());
    }

    [Fact]
    public void Format_ExplicitSeverityPropertyWins()
    {
        var output = Format(CreateEvent(LogEventLevel.Warning, "evento", ("severity", new ScalarValue("high"))));

        using var json = JsonDocument.Parse(output);
        Assert.Equal("high", json.RootElement.GetProperty("severity").GetString());
    }

    [Fact]
    public void Format_RedactsSensitivePropertiesInMessageAndBody()
    {
        var logEvent = CreateEvent(LogEventLevel.Warning, "Login de {username} com senha {password}",
            ("username", new ScalarValue("bob")),
            ("password", new ScalarValue("S3cret!Value")),
            ("api_token", new ScalarValue("tok-123")));

        var output = Format(logEvent);

        Assert.DoesNotContain("S3cret!Value", output);
        Assert.DoesNotContain("tok-123", output);

        using var json = JsonDocument.Parse(output);
        var root = json.RootElement;
        Assert.Equal("Login de bob com senha [REDACTED]", root.GetProperty("message").GetString());
        Assert.Equal("[REDACTED]", root.GetProperty("properties").GetProperty("password").GetString());
        Assert.Equal("[REDACTED]", root.GetProperty("properties").GetProperty("api_token").GetString());
    }

    [Fact]
    public void Format_RedactsSensitiveFieldsInsideStructures()
    {
        var structure = new StructureValue(
        [
            new LogEventProperty("UserName", new ScalarValue("carol")),
            new LogEventProperty("Password", new ScalarValue("hidden-value"))
        ], "LoginRequest");

        var output = Format(CreateEvent(LogEventLevel.Information, "Requisição {@request}", ("request", structure)));

        Assert.DoesNotContain("hidden-value", output);
        using var json = JsonDocument.Parse(output);
        var request = json.RootElement.GetProperty("properties").GetProperty("request");
        Assert.Equal("carol", request.GetProperty("UserName").GetString());
        Assert.Equal("[REDACTED]", request.GetProperty("Password").GetString());
    }

    [Fact]
    public void Format_IncludesExceptionDetails()
    {
        var logEvent = new LogEvent(DateTimeOffset.UtcNow, LogEventLevel.Error, new InvalidOperationException("falhou"),
            Parser.Parse("Erro"), []);

        using var json = JsonDocument.Parse(Format(logEvent));
        var exception = json.RootElement.GetProperty("exception");

        Assert.Equal("System.InvalidOperationException", exception.GetProperty("type").GetString());
        Assert.Equal("falhou", exception.GetProperty("message").GetString());
    }

    [Fact]
    public void Format_EscapesControlCharactersSoLinesCannotBeForged()
    {
        var output = Format(CreateEvent(LogEventLevel.Information, "Busca {term}",
            ("term", new ScalarValue("abc\n{\"event_type\":\"UserLogin\"}"))));

        Assert.Single(output.TrimEnd('\n').Split('\n'));
        using var json = JsonDocument.Parse(output);
        Assert.False(json.RootElement.TryGetProperty("event_type", out _));
    }

    [Fact]
    public void Format_OmitsNullFields()
    {
        var output = Format(CreateEvent(LogEventLevel.Information, "anônimo", ("user_id", new ScalarValue(null))));

        using var json = JsonDocument.Parse(output);
        Assert.False(json.RootElement.TryGetProperty("user_id", out _));
    }

    private static LogEvent CreateEvent(LogEventLevel level, string template, params (string Name, LogEventPropertyValue Value)[] properties) =>
        new(DateTimeOffset.UtcNow, level, null, Parser.Parse(template),
            properties.Select(p => new LogEventProperty(p.Name, p.Value)));

    private static string Format(LogEvent logEvent)
    {
        using var writer = new StringWriter();
        new SiemJsonFormatter("SecureCorpPortal", "Testing", "test-host").Format(logEvent, writer);
        return writer.ToString();
    }
}
