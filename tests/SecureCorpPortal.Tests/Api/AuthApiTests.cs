using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Data;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;
using SecureCorpPortal.Tests.Infrastructure;

namespace SecureCorpPortal.Tests.Api;

public class AuthApiTests : IClassFixture<PortalWebApplicationFactory>
{
    private readonly PortalWebApplicationFactory _factory;

    public AuthApiTests(PortalWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Login_WithValidCredentials_ReturnsUserAndSetsAuthCookie()
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = DemoAccounts.Admin.UserName, password = DemoAccounts.Admin.Password });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.ReadJsonAsync<AuthResponse>();
        Assert.Equal("admin", body.User.UserName);
        Assert.Equal(AppRoles.Admin, body.User.Role);

        var cookies = response.Headers.GetValues("Set-Cookie").ToList();
        var authCookie = Assert.Single(cookies, c => c.StartsWith("SecureCorp.Auth="));
        Assert.Contains("httponly", authCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", authCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_WithWrongPassword_Returns401WithGenericMessage()
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = DemoAccounts.Analyst.UserName, password = "Wrong@123!" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var problem = await response.ReadJsonAsync<ProblemDetails>();
        Assert.Equal(SecureCorpPortal.Services.AuthMessages.InvalidLogin, problem.Title);
    }

    [Fact]
    public async Task Login_WithUnknownUser_ReturnsSameMessageAsWrongPassword()
    {
        using var client = _factory.CreatePortalClient();

        var unknown = await client.PostAsJsonAsync("/api/auth/login", new { userName = "nobody", password = "Wrong@123!" });
        var wrongPassword = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = DemoAccounts.Guest.UserName, password = "Wrong@123!" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(
            (await unknown.ReadJsonAsync<ProblemDetails>()).Title,
            (await wrongPassword.ReadJsonAsync<ProblemDetails>()).Title);
    }

    [Fact]
    public async Task Login_WithMissingFields_Returns400()
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.PostAsJsonAsync("/api/auth/login", new { userName = "" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Me_WithoutAuthentication_Returns401()
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Me_WhenAuthenticated_ReturnsCurrentUser()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var response = await client.GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var me = await response.ReadJsonAsync<UserDto>();
        Assert.Equal(DemoAccounts.Employee.UserName, me.UserName);
        Assert.Equal(AppRoles.Employee, me.Role);
    }

    [Fact]
    public async Task Register_CreatesUserWithGuestRole()
    {
        var user = await _factory.RegisterUserAsync("newcomer1");

        Assert.Equal(AppRoles.Guest, user.Role);
        Assert.True(user.IsActive);

        using var client = await _factory.CreateClientAsAsync("newcomer1", "Temp@12345");
        var me = await (await client.GetAsync("/api/auth/me")).ReadJsonAsync<UserDto>();
        Assert.Equal(AppRoles.Guest, me.Role);
    }

    [Fact]
    public async Task Register_IgnoresRoleSentByClient()
    {
        using var client = _factory.CreatePortalClient();

        // "role" não existe no RegisterRequest: o campo extra é simplesmente ignorado.
        var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName = "sneaky1",
            email = "sneaky1@securecorp.local",
            fullName = "Sneaky",
            password = "Temp@12345",
            confirmPassword = "Temp@12345",
            role = "ADMIN"
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(AppRoles.Guest, (await response.ReadJsonAsync<UserDto>()).Role);
    }

    [Fact]
    public async Task Register_WithWeakPassword_Returns400()
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName = "weakpwd1",
            email = "weakpwd1@securecorp.local",
            fullName = "Weak Password",
            password = "abcdefgh",
            confirmPassword = "abcdefgh"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_WithDuplicateUserName_Returns400()
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName = DemoAccounts.Admin.UserName,
            email = "another-admin@securecorp.local",
            fullName = "Duplicate",
            password = "Temp@12345",
            confirmPassword = "Temp@12345"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Logout_EndsSession()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var logout = await client.PostAsync("/api/auth/logout", null);
        var me = await client.GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [Fact]
    public async Task Login_AfterFiveFailures_LocksAccount()
    {
        await _factory.RegisterUserAsync("lockme1");
        using var client = _factory.CreatePortalClient();

        for (var i = 0; i < 5; i++)
        {
            await client.PostAsJsonAsync("/api/auth/login", new { userName = "lockme1", password = "Wrong@123!" });
        }

        // Mesmo com a senha correta, a conta está bloqueada.
        var response = await client.PostAsJsonAsync("/api/auth/login", new { userName = "lockme1", password = "Temp@12345" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var lockoutEvents = await _factory.QueryDbAsync(db => db.AuditEvents
            .CountAsync(e => e.EventType == AuditEventType.UserLockedOut && e.Username == "lockme1"));
        Assert.True(lockoutEvents >= 1);
    }

    [Fact]
    public async Task Login_InactiveUser_IsRejected()
    {
        var user = await _factory.RegisterUserAsync("inactive1");
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);
        var deactivate = await admin.PutAsJsonAsync($"/api/users/{user.Id}", new { isActive = false });
        Assert.Equal(HttpStatusCode.OK, deactivate.StatusCode);

        using var client = _factory.CreatePortalClient();
        var response = await client.PostAsJsonAsync("/api/auth/login", new { userName = "inactive1", password = "Temp@12345" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
