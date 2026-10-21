using System.Net;
using System.Net.Http.Json;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Data;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Tests.Infrastructure;

namespace SecureCorpPortal.Tests.Api;

public class UsersApiTests : IClassFixture<PortalWebApplicationFactory>
{
    private readonly PortalWebApplicationFactory _factory;

    public UsersApiTests(PortalWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("analyst")]
    public async Task List_AsAdminOrAnalyst_ReturnsUsers(string userName)
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.ByUserName(userName));

        var response = await client.GetAsync("/api/users");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var users = await response.ReadJsonAsync<List<UserDto>>();
        Assert.Contains(users, u => u.UserName == "admin" && u.Role == AppRoles.Admin);
        Assert.Contains(users, u => u.UserName == "employee" && u.Role == AppRoles.Employee);
    }

    [Theory]
    [InlineData("employee")]
    [InlineData("guest")]
    public async Task List_AsEmployeeOrGuest_Returns403(string userName)
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.ByUserName(userName));

        var response = await client.GetAsync("/api/users");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task UserDto_NeverExposesInternalIdentityFields()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Admin);

        var json = await client.GetStringAsync("/api/users");

        Assert.DoesNotContain("passwordHash", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("securityStamp", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("concurrencyStamp", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Employee_CanReadOwnProfile_ButNotOthers()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);
        var me = await (await client.GetAsync("/api/auth/me")).ReadJsonAsync<UserDto>();
        var adminId = await AdminIdAsync();

        var own = await client.GetAsync($"/api/users/{me.Id}");
        var other = await client.GetAsync($"/api/users/{adminId}");

        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, other.StatusCode);
    }

    [Fact]
    public async Task Employee_CanUpdateOwnProfile()
    {
        var user = await _factory.RegisterUserAsync("selfedit1");
        using var client = await _factory.CreateClientAsAsync("selfedit1", "Temp@12345");

        var response = await client.PutAsJsonAsync($"/api/users/{user.Id}",
            new { fullName = "Nome Atualizado", jobTitle = "Analista Júnior" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var updated = await response.ReadJsonAsync<UserDto>();
        Assert.Equal("Nome Atualizado", updated.FullName);
        Assert.Equal("Analista Júnior", updated.JobTitle);
    }

    [Fact]
    public async Task NonAdmin_CannotChangeOwnRole()
    {
        var user = await _factory.RegisterUserAsync("escalate1");
        using var client = await _factory.CreateClientAsAsync("escalate1", "Temp@12345");

        var response = await client.PutAsJsonAsync($"/api/users/{user.Id}", new { role = "ADMIN" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var me = await (await client.GetAsync("/api/auth/me")).ReadJsonAsync<UserDto>();
        Assert.Equal(AppRoles.Guest, me.Role);
    }

    [Fact]
    public async Task NonAdmin_CannotUpdateAnotherUser()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);
        var adminId = await AdminIdAsync();

        var response = await client.PutAsJsonAsync($"/api/users/{adminId}", new { fullName = "Hacked" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Admin_CanChangeRole()
    {
        var user = await _factory.RegisterUserAsync("promote1");
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);

        var response = await admin.PutAsJsonAsync($"/api/users/{user.Id}", new { role = "analyst" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(AppRoles.Analyst, (await response.ReadJsonAsync<UserDto>()).Role);
    }

    [Fact]
    public async Task Admin_InvalidRole_Returns400()
    {
        var user = await _factory.RegisterUserAsync("badrole1");
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);

        var response = await admin.PutAsJsonAsync($"/api/users/{user.Id}", new { role = "SUPERUSER" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Admin_CannotDemoteOrDeleteSelf()
    {
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);
        var adminId = await AdminIdAsync();

        var demote = await admin.PutAsJsonAsync($"/api/users/{adminId}", new { role = "GUEST" });
        var delete = await admin.DeleteAsync($"/api/users/{adminId}");

        Assert.Equal(HttpStatusCode.BadRequest, demote.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, delete.StatusCode);
    }

    [Fact]
    public async Task Admin_CanDeleteUser()
    {
        var user = await _factory.RegisterUserAsync("deleteme1");
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);

        var delete = await admin.DeleteAsync($"/api/users/{user.Id}");
        var get = await admin.GetAsync($"/api/users/{user.Id}");

        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, get.StatusCode);
    }

    [Fact]
    public async Task Employee_CannotDeleteUsers()
    {
        var user = await _factory.RegisterUserAsync("survivor1");
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var response = await client.DeleteAsync($"/api/users/{user.Id}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private async Task<int> AdminIdAsync()
    {
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);
        return (await (await admin.GetAsync("/api/auth/me")).ReadJsonAsync<UserDto>()).Id;
    }
}
