using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureCorpPortal.Data;
using SecureCorpPortal.Middleware;
using SecureCorpPortal.Tests.Infrastructure;

namespace SecureCorpPortal.Tests.Logging;

/// <summary>
/// Executa requisições reais e lê os arquivos JSON gerados em /logs,
/// validando o que de fato chegaria a um SIEM.
/// </summary>
public class LogFileIntegrationTests : IClassFixture<PortalWebApplicationFactory>
{
    private readonly PortalWebApplicationFactory _factory;

    public LogFileIntegrationTests(PortalWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task FailedLogin_IsWrittenAsAuditEvent_WithoutThePassword()
    {
        const string password = "Wr0ng#Pass-987";
        using var client = _factory.CreatePortalClient();
        await client.PostAsJsonAsync("/api/auth/login", new { userName = "employee", password });

        var mainLog = await ReadLogAsync("securecorp-*.json");

        Assert.DoesNotContain(password, mainLog.Raw);
        var entry = Assert.Single(mainLog.Entries, e =>
            Str(e, "event_type") == "UserLoginFailed" && Str(e, "username") == "employee");

        Assert.Equal("audit", Str(entry, "event_category"));
        Assert.Equal("auth.login", Str(entry, "action"));
        Assert.Equal("failure", Str(entry, "outcome"));
        Assert.Equal("medium", Str(entry, "severity"));
        Assert.Equal("POST", Str(entry, "http_method"));
        Assert.Equal("/api/auth/login", Str(entry, "endpoint"));
        Assert.False(string.IsNullOrEmpty(Str(entry, "request_id")));
        Assert.True(entry.TryGetProperty("timestamp", out _));
    }

    [Fact]
    public async Task SuccessfulLogin_IncludesUserIdInAuditEvent()
    {
        await _factory.CreateClientAsAsync(DemoAccounts.Analyst);

        var log = await ReadLogAsync("securecorp-*.json");

        var entry = log.Entries.Last(e => Str(e, "event_type") == "UserLogin" && Str(e, "username") == "analyst");
        Assert.True(entry.GetProperty("user_id").GetInt32() > 0);
        Assert.Equal("success", Str(entry, "outcome"));
    }

    [Fact]
    public async Task EveryRequest_ProducesHttpRequestEvent_CorrelatedByRequestId()
    {
        const string requestId = "lab-test-request-0001";
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/dashboard");
        request.Headers.Add(CorrelationMiddleware.RequestIdHeader, requestId);

        var response = await client.SendAsync(request);

        Assert.Equal(requestId, response.Headers.GetValues(CorrelationMiddleware.RequestIdHeader).Single());

        var log = await ReadLogAsync("securecorp-*.json");
        var http = Assert.Single(log.Entries, e => Str(e, "request_id") == requestId && Str(e, "event_type") == "HttpRequest");

        Assert.Equal("http", Str(http, "event_category"));
        Assert.Equal(200, http.GetProperty("status_code").GetInt32());
        Assert.Equal("employee", Str(http, "username"));
        Assert.Equal("GET", Str(http, "http_method"));
        Assert.Equal("/api/dashboard", Str(http, "endpoint"));
        Assert.True(http.GetProperty("duration_ms").GetDouble() >= 0);
    }

    [Fact]
    public async Task QueryString_IsLoggedForDetection_WithSensitiveParametersMasked()
    {
        const string requestId = "lab-test-query-0001";
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/documents?q=%27%20OR%201%3D1--&token=segredo-xyz");
        request.Headers.Add(CorrelationMiddleware.RequestIdHeader, requestId);

        await client.SendAsync(request);

        var log = await ReadLogAsync("securecorp-*.json");
        Assert.DoesNotContain("segredo-xyz", log.Raw);
        var http = Assert.Single(log.Entries, e => Str(e, "request_id") == requestId && Str(e, "event_type") == "HttpRequest");
        Assert.Equal("/api/documents", Str(http, "endpoint"));
        Assert.Equal("q=%27%20OR%201%3D1--&token=[REDACTED]", Str(http, "query_string"));
    }

    [Fact]
    public async Task InvalidRequestIdHeader_IsReplacedByGeneratedId()
    {
        using var client = _factory.CreatePortalClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/login");
        request.Headers.TryAddWithoutValidation(CorrelationMiddleware.RequestIdHeader, "bad id with spaces");

        var response = await client.SendAsync(request);

        var returned = response.Headers.GetValues(CorrelationMiddleware.RequestIdHeader).Single();
        Assert.NotEqual("bad id with spaces", returned);
        Assert.Matches("^[a-f0-9]{32}$", returned);
    }

    [Fact]
    public async Task RejectedRequestIdHeader_IsRecordedSanitized()
    {
        const string forged = "bad id; with spaces";
        using var client = _factory.CreatePortalClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/login");
        request.Headers.TryAddWithoutValidation(CorrelationMiddleware.RequestIdHeader, forged);

        var response = await client.SendAsync(request);
        var generated = response.Headers.GetValues(CorrelationMiddleware.RequestIdHeader).Single();

        var log = await ReadLogAsync("securecorp-*.json");
        var http = Assert.Single(log.Entries, e => Str(e, "request_id") == generated && Str(e, "event_type") == "HttpRequest");
        Assert.Equal(forged, http.GetProperty("properties").GetProperty("request_id_rejected").GetString());
    }

    [Fact]
    public async Task SessionRef_CorrelatesRequestsOfTheSameSession_WithoutLoggingTheCookie()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        var login = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = DemoAccounts.Employee.UserName, password = DemoAccounts.Employee.Password });
        var setCookie = login.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("SecureCorp.Auth=", StringComparison.Ordinal));
        var cookieValue = setCookie.Split(';')[0]["SecureCorp.Auth=".Length..];

        string[] requestIds = ["lab-test-session-0001", "lab-test-session-0002"];
        foreach (var requestId in requestIds)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
            request.Headers.Add("Cookie", $"SecureCorp.Auth={cookieValue}");
            request.Headers.Add(CorrelationMiddleware.RequestIdHeader, requestId);
            Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(request)).StatusCode);
        }

        var log = await ReadLogAsync("securecorp-*.json");
        var refs = requestIds
            .Select(id => Assert.Single(log.Entries, e => Str(e, "request_id") == id && Str(e, "event_type") == "HttpRequest"))
            .Select(e => Str(e, "session_ref"))
            .ToList();

        Assert.Matches("^[a-f0-9]{16}$", refs[0]!);
        Assert.Equal(refs[0], refs[1]);
        Assert.DoesNotContain(cookieValue, log.Raw);
    }

    [Fact]
    public async Task Request_WithoutSessionCookie_HasNoSessionRef()
    {
        const string requestId = "lab-test-nosession-0001";
        using var client = _factory.CreatePortalClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/login");
        request.Headers.Add(CorrelationMiddleware.RequestIdHeader, requestId);

        await client.SendAsync(request);

        var log = await ReadLogAsync("securecorp-*.json");
        var http = Assert.Single(log.Entries, e => Str(e, "request_id") == requestId && Str(e, "event_type") == "HttpRequest");
        Assert.Null(Str(http, "session_ref"));
    }

    [Fact]
    public async Task OriginHeaders_AreLogged_AndRefererLosesItsQueryString()
    {
        const string requestId = "lab-test-origin-0001";
        using var client = _factory.CreatePortalClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/login");
        request.Headers.Add(CorrelationMiddleware.RequestIdHeader, requestId);
        request.Headers.Add("Origin", "http://localhost:9999");
        request.Headers.Add("Sec-Fetch-Site", "cross-site");
        request.Headers.Add("Referer", "http://localhost:9999/page?token=do-not-log");

        await client.SendAsync(request);

        var log = await ReadLogAsync("securecorp-*.json");
        Assert.DoesNotContain("do-not-log", log.Raw);
        var http = Assert.Single(log.Entries, e => Str(e, "request_id") == requestId && Str(e, "event_type") == "HttpRequest");
        Assert.Equal("http://localhost:9999", Str(http, "origin"));
        Assert.Equal("cross-site", Str(http, "sec_fetch_site"));
        Assert.Equal("http://localhost:9999/page", Str(http, "referer"));
    }

    [Fact]
    public async Task AntiforgeryFailure_IsWrittenAsAccessDeniedAuditEvent()
    {
        const string requestId = "lab-test-csrf-0001";
        using var client = _factory.CreatePortalClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["UserName"] = DemoAccounts.Employee.UserName,
                ["Password"] = "Wrong@123!"
            })
        };
        request.Headers.Add(CorrelationMiddleware.RequestIdHeader, requestId);

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var log = await ReadLogAsync("security-*.json");
        var audit = Assert.Single(log.Entries, e => Str(e, "request_id") == requestId);
        Assert.Equal("AccessDenied", Str(audit, "event_type"));
        Assert.Equal("csrf.validation_failed", Str(audit, "action"));
        Assert.Equal("failure", Str(audit, "outcome"));
        Assert.Equal("/login", Str(audit, "resource"));
    }

    [Fact]
    public async Task SecurityLog_ContainsOnlyAuditAndSecurityEvents()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Guest);
        await client.GetAsync("/api/admin/users");   // gera AccessDenied
        await client.GetAsync("/api/dashboard");     // gera apenas HttpRequest

        var securityLog = await ReadLogAsync("security-*.json");

        Assert.NotEmpty(securityLog.Entries);
        Assert.All(securityLog.Entries, e => Assert.Contains(Str(e, "event_category"), new[] { "audit", "security" }));
        Assert.Contains(securityLog.Entries, e => Str(e, "event_type") == "AccessDenied" && Str(e, "username") == "guest");
    }

    private async Task<(string Raw, List<JsonElement> Entries)> ReadLogAsync(string pattern)
    {
        // A escrita é síncrona, mas damos uma pequena margem ao sistema de arquivos.
        for (var attempt = 0; ; attempt++)
        {
            var files = Directory.Exists(_factory.LogDirectory)
                ? Directory.GetFiles(_factory.LogDirectory, pattern)
                : [];

            var raw = string.Concat(files.Select(ReadShared));
            if (raw.Length > 0 || attempt >= 20)
            {
                var entries = raw
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(line => JsonDocument.Parse(line).RootElement.Clone())
                    .ToList();
                return (raw, entries);
            }

            await Task.Delay(100);
        }
    }

    private static string ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string? Str(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
