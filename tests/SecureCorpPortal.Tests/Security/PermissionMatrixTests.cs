using System.Net;
using SecureCorpPortal.Data;
using SecureCorpPortal.Tests.Infrastructure;

namespace SecureCorpPortal.Tests.Security;

/// <summary>
/// Verifica a matriz de permissões documentada em docs/security/permissions.md:
/// para cada papel e endpoint GET, o status HTTP esperado.
/// </summary>
public class PermissionMatrixTests : IClassFixture<PortalWebApplicationFactory>
{
    private readonly PortalWebApplicationFactory _factory;

    public PermissionMatrixTests(PortalWebApplicationFactory factory)
    {
        _factory = factory;
    }

    public static TheoryData<string, string, HttpStatusCode> ApiMatrix => new()
    {
        // usuário    endpoint            status esperado
        { "admin",    "/api/users",       HttpStatusCode.OK },
        { "analyst",  "/api/users",       HttpStatusCode.OK },
        { "employee", "/api/users",       HttpStatusCode.Forbidden },
        { "guest",    "/api/users",       HttpStatusCode.Forbidden },

        { "admin",    "/api/admin/users", HttpStatusCode.OK },
        { "analyst",  "/api/admin/users", HttpStatusCode.Forbidden },
        { "employee", "/api/admin/users", HttpStatusCode.Forbidden },
        { "guest",    "/api/admin/users", HttpStatusCode.Forbidden },

        { "admin",    "/api/admin/logs",  HttpStatusCode.OK },
        { "analyst",  "/api/admin/logs",  HttpStatusCode.Forbidden },
        { "employee", "/api/admin/logs",  HttpStatusCode.Forbidden },
        { "guest",    "/api/admin/logs",  HttpStatusCode.Forbidden },

        { "admin",    "/api/documents",   HttpStatusCode.OK },
        { "analyst",  "/api/documents",   HttpStatusCode.OK },
        { "employee", "/api/documents",   HttpStatusCode.OK },
        { "guest",    "/api/documents",   HttpStatusCode.OK },

        { "admin",    "/api/dashboard",   HttpStatusCode.OK },
        { "analyst",  "/api/dashboard",   HttpStatusCode.OK },
        { "employee", "/api/dashboard",   HttpStatusCode.OK },
        { "guest",    "/api/dashboard",   HttpStatusCode.OK }
    };

    [Theory]
    [MemberData(nameof(ApiMatrix))]
    public async Task Api_RespectsRoleMatrix(string userName, string endpoint, HttpStatusCode expected)
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.ByUserName(userName));

        var response = await client.GetAsync(endpoint);

        Assert.Equal(expected, response.StatusCode);
    }

    public static TheoryData<string, string, bool> PageMatrix => new()
    {
        // true = página acessível; false = redireciona para /access-denied
        { "admin",    "/users",            true },
        { "analyst",  "/users",            true },
        { "employee", "/users",            false },
        { "guest",    "/users",            false },

        { "admin",    "/admin",            true },
        { "analyst",  "/admin",            false },
        { "employee", "/admin/logs",       false },
        { "guest",    "/admin/users",      false },

        { "admin",    "/documents/upload", true },
        { "analyst",  "/documents/upload", true },
        { "employee", "/documents/upload", true },
        { "guest",    "/documents/upload", false }
    };

    [Theory]
    [MemberData(nameof(PageMatrix))]
    public async Task Pages_RespectRoleMatrix(string userName, string path, bool allowed)
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.ByUserName(userName));

        var response = await client.GetAsync(path);

        if (allowed)
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        else
        {
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.StartsWith("/access-denied", response.Headers.Location!.PathAndQuery);
        }
    }

    [Theory]
    [InlineData("/api/users")]
    [InlineData("/api/documents")]
    [InlineData("/api/dashboard")]
    [InlineData("/api/admin/logs")]
    public async Task Api_WithoutAuthentication_Returns401(string endpoint)
    {
        using var client = _factory.CreatePortalClient();

        var response = await client.GetAsync(endpoint);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
