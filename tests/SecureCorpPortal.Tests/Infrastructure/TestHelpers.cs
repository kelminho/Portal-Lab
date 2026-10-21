using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecureCorpPortal.Data;
using SecureCorpPortal.DTOs;

namespace SecureCorpPortal.Tests.Infrastructure;

public static class TestHelpers
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>Cliente sem redirecionamento automático (para inspecionar 302) e com cookies.</summary>
    public static HttpClient CreatePortalClient(this PortalWebApplicationFactory factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

    /// <summary>Cria um cliente já autenticado via POST /api/auth/login.</summary>
    public static async Task<HttpClient> CreateClientAsAsync(this PortalWebApplicationFactory factory, string userName, string password)
    {
        var client = factory.CreatePortalClient();
        var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return client;
    }

    public static Task<HttpClient> CreateClientAsAsync(this PortalWebApplicationFactory factory, DemoAccounts.DemoAccount account) =>
        factory.CreateClientAsAsync(account.UserName, account.Password);

    public static async Task<T> ReadJsonAsync<T>(this HttpResponseMessage response)
    {
        var value = await response.Content.ReadFromJsonAsync<T>(Json);
        Assert.NotNull(value);
        return value!;
    }

    /// <summary>Registra um novo usuário (papel GUEST) e devolve seus dados.</summary>
    public static async Task<UserDto> RegisterUserAsync(this PortalWebApplicationFactory factory, string userName, string password = "Temp@12345")
    {
        using var client = factory.CreatePortalClient();
        var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = $"{userName}@securecorp.local",
            fullName = $"Usuário {userName}",
            department = "Testes",
            password,
            confirmPassword = password
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await response.ReadJsonAsync<UserDto>();
    }

    /// <summary>Executa uma consulta direta no banco InMemory da aplicação.</summary>
    public static async Task<T> QueryDbAsync<T>(this PortalWebApplicationFactory factory, Func<AppDbContext, Task<T>> query)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        return await query(db);
    }

    /// <summary>Extrai o token antiforgery de um formulário HTML renderizado.</summary>
    public static string ExtractAntiforgeryToken(string html)
    {
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"");
        Assert.True(match.Success, "Token antiforgery não encontrado no HTML.");
        return match.Groups[1].Value;
    }
}
