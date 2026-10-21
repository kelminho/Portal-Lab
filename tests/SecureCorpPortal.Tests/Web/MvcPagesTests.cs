using System.Net;
using SecureCorpPortal.Data;
using SecureCorpPortal.Tests.Infrastructure;

namespace SecureCorpPortal.Tests.Web;

public class MvcPagesTests : IClassFixture<PortalWebApplicationFactory>
{
    private readonly PortalWebApplicationFactory _factory;

    public MvcPagesTests(PortalWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Root_WhenAnonymous_RedirectsToLogin()
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.GetAsync("/");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/login", response.Headers.Location!.OriginalString);
    }

    [Theory]
    [InlineData("/dashboard")]
    [InlineData("/profile")]
    [InlineData("/documents")]
    [InlineData("/search")]
    public async Task ProtectedPages_WhenAnonymous_RedirectToLogin(string path)
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("/login", response.Headers.Location!.PathAndQuery);
    }

    [Theory]
    [InlineData("/login")]
    [InlineData("/register")]
    public async Task PublicPages_RenderFormWithAntiforgeryToken(string path)
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.GetAsync(path);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("__RequestVerificationToken", html);
    }

    [Fact]
    public async Task LoginForm_WithoutAntiforgeryToken_IsRejected()
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = DemoAccounts.Admin.UserName,
            ["Password"] = DemoAccounts.Admin.Password
        }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task LoginForm_WithValidCredentials_RedirectsToDashboard()
    {
        using var client = _factory.CreatePortalClient();
        var token = TestHelpers.ExtractAntiforgeryToken(await client.GetStringAsync("/login"));

        var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = DemoAccounts.Admin.UserName,
            ["Password"] = DemoAccounts.Admin.Password,
            ["__RequestVerificationToken"] = token
        }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/dashboard", response.Headers.Location!.OriginalString);

        var dashboard = await client.GetStringAsync("/dashboard");
        Assert.Contains(DemoAccounts.Admin.FullName, dashboard);
    }

    [Fact]
    public async Task LoginForm_WithExternalReturnUrl_DoesNotRedirectOutside()
    {
        using var client = _factory.CreatePortalClient();
        var token = TestHelpers.ExtractAntiforgeryToken(await client.GetStringAsync("/login"));

        var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = DemoAccounts.Employee.UserName,
            ["Password"] = DemoAccounts.Employee.Password,
            ["ReturnUrl"] = "https://example.com/phishing",
            ["__RequestVerificationToken"] = token
        }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/dashboard", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task LoginForm_WithInvalidCredentials_ShowsGenericError()
    {
        using var client = _factory.CreatePortalClient();
        var token = TestHelpers.ExtractAntiforgeryToken(await client.GetStringAsync("/login"));

        var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = DemoAccounts.Employee.UserName,
            ["Password"] = "Wrong@123!",
            ["__RequestVerificationToken"] = token
        }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Usuário ou senha inválidos", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("employee", "/dashboard")]
    [InlineData("employee", "/documents")]
    [InlineData("employee", "/profile")]
    [InlineData("employee", "/search?q=manual")]
    [InlineData("admin", "/admin")]
    [InlineData("admin", "/admin/users")]
    [InlineData("admin", "/admin/logs")]
    [InlineData("analyst", "/users")]
    public async Task AuthenticatedPages_Render(string userName, string path)
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.ByUserName(userName));

        var response = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("SecureCorp", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task DocumentPage_AboveClearance_Returns403Page()
    {
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);
        var adminHtml = await admin.GetStringAsync("/documents?q=Plano%20Estrat");
        var match = System.Text.RegularExpressions.Regex.Match(adminHtml, "href=\"/documents/(\\d+)\"");
        Assert.True(match.Success);

        using var guest = await _factory.CreateClientAsAsync(DemoAccounts.Guest);
        var response = await guest.GetAsync($"/documents/{match.Groups[1].Value}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("Acesso negado", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task UnknownPage_Returns404Page()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var response = await client.GetAsync("/does-not-exist");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Contains("Página não encontrada", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Responses_IncludeSecurityHeaders()
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.GetAsync("/login");

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("default-src 'self'", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.True(response.Headers.Contains("X-Request-ID"));
    }

    [Fact]
    public async Task HealthEndpoint_IsAvailable()
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
