using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using SecureCorpPortal.Data;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;
using SecureCorpPortal.Tests.Infrastructure;

namespace SecureCorpPortal.Tests.Audit;

/// <summary>Garante que ações relevantes geram eventos na tabela audit_events.</summary>
public class AuditTrailTests : IClassFixture<PortalWebApplicationFactory>
{
    private readonly PortalWebApplicationFactory _factory;

    public AuditTrailTests(PortalWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task SuccessfulLogin_RecordsUserLogin()
    {
        await _factory.CreateClientAsAsync(DemoAccounts.Analyst);

        var events = await EventsAsync(AuditEventType.UserLogin, "analyst");

        var last = events.Last();
        Assert.True(last.Success);
        Assert.NotNull(last.UserId);
        Assert.Equal("auth.login", last.Action);
        Assert.Equal("/api/auth/login", last.Endpoint);
        Assert.Equal("POST", last.HttpMethod);
        Assert.False(string.IsNullOrEmpty(last.RequestId));
    }

    [Fact]
    public async Task FailedLogin_RecordsUserLoginFailedWithMediumSeverity()
    {
        using var client = _factory.CreatePortalClient();
        await client.PostAsJsonAsync("/api/auth/login", new { userName = "employee", password = "Wrong@123!" });

        var last = (await EventsAsync(AuditEventType.UserLoginFailed, "employee")).Last();

        Assert.False(last.Success);
        Assert.Equal(AuditSeverity.Medium, last.Severity);
        Assert.Equal("Senha inválida.", last.Details);
    }

    [Fact]
    public async Task FailedLogin_ForUnknownUser_RecordsAttemptedUsername()
    {
        using var client = _factory.CreatePortalClient();
        await client.PostAsJsonAsync("/api/auth/login", new { userName = "ghost.user", password = "Wrong@123!" });

        var last = (await EventsAsync(AuditEventType.UserLoginFailed, "ghost.user")).Last();

        Assert.Null(last.UserId);
        Assert.Equal("Usuário inexistente.", last.Details);
    }

    [Fact]
    public async Task Logout_RecordsUserLogout()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Guest);
        await client.PostAsync("/api/auth/logout", null);

        Assert.NotEmpty(await EventsAsync(AuditEventType.UserLogout, "guest"));
    }

    [Fact]
    public async Task Registration_RecordsUserCreated()
    {
        await _factory.RegisterUserAsync("audited1");

        var last = (await EventsAsync(AuditEventType.UserCreated, "audited1")).Last();
        Assert.Equal("user.self_registered", last.Action);
    }

    [Fact]
    public async Task RoleChange_RecordsRoleChangedWithHighSeverity()
    {
        var user = await _factory.RegisterUserAsync("rolechange1");
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);
        await admin.PutAsJsonAsync($"/api/users/{user.Id}", new { role = "EMPLOYEE" });

        var last = (await EventsAsync(AuditEventType.RoleChanged, "admin")).Last();

        Assert.Equal(AuditSeverity.High, last.Severity);
        Assert.Equal($"user:{user.Id}", last.Resource);
        Assert.Contains("GUEST", last.Details);
        Assert.Contains("EMPLOYEE", last.Details);
    }

    [Fact]
    public async Task ProfileUpdate_RecordsUserUpdatedWithChangedFields()
    {
        var user = await _factory.RegisterUserAsync("updater1");
        using var client = await _factory.CreateClientAsAsync("updater1", "Temp@12345");
        await client.PutAsJsonAsync($"/api/users/{user.Id}", new { jobTitle = "Coordenador" });

        var last = (await EventsAsync(AuditEventType.UserUpdated, "updater1")).Last();

        Assert.Contains("job_title", last.Details);
    }

    [Fact]
    public async Task PrivilegeEscalationAttempt_RecordsAccessDeniedWithHighSeverity()
    {
        var user = await _factory.RegisterUserAsync("escalator1");
        using var client = await _factory.CreateClientAsAsync("escalator1", "Temp@12345");
        await client.PutAsJsonAsync($"/api/users/{user.Id}", new { role = "ADMIN" });

        var last = (await EventsAsync(AuditEventType.AccessDenied, "escalator1")).Last();

        Assert.Equal("user.privilege_change_denied", last.Action);
        Assert.Equal(AuditSeverity.High, last.Severity);
    }

    [Fact]
    public async Task PolicyDenied_RecordsAccessDenied()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);
        await client.GetAsync("/api/admin/logs");

        var last = (await EventsAsync(AuditEventType.AccessDenied, "employee")).Last();

        Assert.Equal("authorization.policy_denied", last.Action);
        Assert.Equal("/api/admin/logs", last.Resource);
    }

    [Fact]
    public async Task DocumentRead_RecordsDocumentAccessed_AndDenialRecordsAccessDenied()
    {
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);
        var documents = await (await admin.GetAsync("/api/documents")).ReadJsonAsync<List<DocumentDto>>();
        var restricted = documents.First(d => d.Classification == DocumentClassification.Restricted);

        await admin.GetAsync($"/api/documents/{restricted.Id}");
        using var guest = await _factory.CreateClientAsAsync(DemoAccounts.Guest);
        await guest.GetAsync($"/api/documents/{restricted.Id}");

        var accessed = (await EventsAsync(AuditEventType.DocumentAccessed, "admin")).Last();
        var denied = (await EventsAsync(AuditEventType.AccessDenied, "guest")).Last();

        Assert.Equal($"document:{restricted.Id}", accessed.Resource);
        Assert.Equal("document.read_denied", denied.Action);
        Assert.Equal($"document:{restricted.Id}", denied.Resource);
    }

    [Fact]
    public async Task Upload_RecordsDocumentUploaded_AndRejectedUploadRecordsFailure()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        await client.PostAsync("/api/documents/upload", Upload("ok.txt", "texto"u8.ToArray()));
        await client.PostAsync("/api/documents/upload", Upload("bad.exe", "MZ"u8.ToArray()));

        var events = await EventsAsync(AuditEventType.DocumentUploaded, "employee");

        Assert.Contains(events, e => e.Success && e.Details!.Contains("ok.txt"));
        Assert.Contains(events, e => !e.Success && e.Details!.Contains(".exe"));
    }

    [Fact]
    public async Task Upload_WithTraversalFileName_RecordsTheNameSentByTheClient()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        await client.PostAsync("/api/documents/upload", Upload("../../traversal.txt", "texto"u8.ToArray()));
        await client.PostAsync("/api/documents/upload", Upload("../../bad.exe", "MZ"u8.ToArray()));

        var events = await EventsAsync(AuditEventType.DocumentUploaded, "employee");

        Assert.Contains(events, e => e.Success && e.Details!.Contains("Arquivo 'traversal.txt'") &&
                                     e.Details.Contains("Nome enviado pelo cliente: '../../traversal.txt'"));
        Assert.Contains(events, e => !e.Success && e.Details!.Contains("Nome enviado pelo cliente: '../../bad.exe'"));
    }

    [Fact]
    public async Task Login_WithExternalReturnUrl_RecordsBlockedRedirectAttempt()
    {
        using var client = _factory.CreatePortalClient();
        var token = TestHelpers.ExtractAntiforgeryToken(await client.GetStringAsync("/login"));

        var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = DemoAccounts.Sales.UserName,
            ["Password"] = DemoAccounts.Sales.Password,
            ["ReturnUrl"] = "https://evil.test/phish",
            ["__RequestVerificationToken"] = token
        }));

        Assert.Equal("/dashboard", response.Headers.Location!.OriginalString);
        var blocked = (await EventsAsync(AuditEventType.AccessDenied, DemoAccounts.Sales.UserName)).Last();
        Assert.Equal("login.external_return_url_blocked", blocked.Action);
        Assert.Equal("https://evil.test/phish", blocked.Resource);
        Assert.False(blocked.Success);
    }

    [Fact]
    public async Task AuditTrail_NeverContainsPasswords()
    {
        const string secret = "Sup3r$ecretValue!";
        using var client = _factory.CreatePortalClient();
        await client.PostAsJsonAsync("/api/auth/login", new { userName = "admin", password = secret });
        await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName = "pwdcheck1",
            email = "pwdcheck1@securecorp.local",
            fullName = "Pwd Check",
            password = secret,
            confirmPassword = secret
        });

        var leaked = await _factory.QueryDbAsync(db => db.AuditEvents
            .Where(e => (e.Details != null && e.Details.Contains(secret)) || (e.Username != null && e.Username.Contains(secret)))
            .CountAsync());

        Assert.Equal(0, leaked);
    }

    [Fact]
    public async Task AdminViewingLogs_IsItselfAudited()
    {
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);
        await admin.GetAsync("/api/admin/logs");

        var events = await EventsAsync(AuditEventType.AdminAction, "admin");
        Assert.Contains(events, e => e.Action == "audit_log.viewed");
    }

    private Task<List<AuditEvent>> EventsAsync(AuditEventType type, string username) =>
        _factory.QueryDbAsync(db => db.AuditEvents
            .Where(e => e.EventType == type && e.Username == username)
            .OrderBy(e => e.Id)
            .ToListAsync());

    private static MultipartFormDataContent Upload(string fileName, byte[] bytes)
    {
        var file = new ByteArrayContent(bytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return new MultipartFormDataContent
        {
            { new StringContent("Arquivo de teste"), "Title" },
            { new StringContent("Internal"), "Classification" },
            { file, "File", fileName }
        };
    }
}
