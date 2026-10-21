using System.Net;
using System.Net.Http.Json;
using SecureCorpPortal.Data;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;
using SecureCorpPortal.Tests.Infrastructure;

namespace SecureCorpPortal.Tests.Api;

public class AdminAndDashboardApiTests : IClassFixture<PortalWebApplicationFactory>
{
    private readonly PortalWebApplicationFactory _factory;

    public AdminAndDashboardApiTests(PortalWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task AdminUsers_IncludesLockoutFields()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Admin);

        var response = await client.GetAsync("/api/admin/users");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var users = await response.ReadJsonAsync<List<AdminUserDto>>();
        Assert.Equal(DemoAccounts.All.Count, users.Count(u => DemoAccounts.All.Any(a => a.UserName == u.UserName)));
        Assert.All(users, u => Assert.True(u.AccessFailedCount >= 0));
    }

    [Fact]
    public async Task AdminLogs_ReturnsPagedAuditEvents()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Admin);

        var response = await client.GetAsync("/api/admin/logs?pageSize=5");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.ReadJsonAsync<PagedResult<AuditEventDto>>();
        Assert.Equal(1, page.Page);
        Assert.Equal(5, page.PageSize);
        Assert.True(page.TotalCount >= 1);
        Assert.InRange(page.Items.Count, 1, 5);
    }

    [Fact]
    public async Task AdminLogs_FiltersByEventType()
    {
        using (var anonymous = _factory.CreatePortalClient())
        {
            await anonymous.PostAsJsonAsync("/api/auth/login", new { userName = "guest", password = "Wrong@123!" });
        }

        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Admin);
        var page = await (await client.GetAsync("/api/admin/logs?eventType=UserLoginFailed"))
            .ReadJsonAsync<PagedResult<AuditEventDto>>();

        Assert.NotEmpty(page.Items);
        Assert.All(page.Items, e => Assert.Equal(AuditEventType.UserLoginFailed, e.EventType));
    }

    [Theory]
    [InlineData("analyst")]
    [InlineData("employee")]
    [InlineData("guest")]
    public async Task AdminEndpoints_ForNonAdmins_Return403(string userName)
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.ByUserName(userName));

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/admin/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/admin/logs")).StatusCode);
    }

    [Fact]
    public async Task Dashboard_ForAdmin_IncludesAnalyticsAndAuditEvents()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Admin);

        var dashboard = await (await client.GetAsync("/api/dashboard")).ReadJsonAsync<DashboardDto>();

        Assert.NotNull(dashboard.Analytics);
        Assert.NotNull(dashboard.RecentAuditEvents);
        Assert.True(dashboard.Analytics!.TotalUsers >= DemoAccounts.All.Count);
        Assert.Equal(10, dashboard.VisibleDocuments);
    }

    [Fact]
    public async Task Dashboard_ForAnalyst_IncludesAnalyticsButNotAuditEvents()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Analyst);

        var dashboard = await (await client.GetAsync("/api/dashboard")).ReadJsonAsync<DashboardDto>();

        Assert.NotNull(dashboard.Analytics);
        Assert.Null(dashboard.RecentAuditEvents);
    }

    [Theory]
    [InlineData("employee")]
    [InlineData("guest")]
    public async Task Dashboard_ForRegularUsers_HasNoSecurityData(string userName)
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.ByUserName(userName));

        var dashboard = await (await client.GetAsync("/api/dashboard")).ReadJsonAsync<DashboardDto>();

        Assert.Null(dashboard.Analytics);
        Assert.Null(dashboard.RecentAuditEvents);
        Assert.Equal(userName, dashboard.User.UserName);
    }
}
