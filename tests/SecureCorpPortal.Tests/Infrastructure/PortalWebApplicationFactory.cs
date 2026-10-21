using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecureCorpPortal.Data;

namespace SecureCorpPortal.Tests.Infrastructure;

/// <summary>
/// Sobe a aplicação real (Program.cs) em memória para testes de integração.
/// Diferenças em relação à execução normal:
/// - banco EF Core InMemory (um por instância da factory → testes isolados);
/// - logs e uploads em um diretório temporário exclusivo;
/// - seed de demonstração sempre habilitado.
/// </summary>
public sealed class PortalWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _databaseName = "securecorp-tests-" + Guid.NewGuid().ToString("N");

    public string WorkDirectory { get; } =
        Path.Combine(Path.GetTempPath(), "securecorp-tests", Guid.NewGuid().ToString("N"));

    public string LogDirectory => Path.Combine(WorkDirectory, "logs");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:DefaultConnection", "Host=not-used-in-tests");
        builder.UseSetting("AppLogging:Directory", LogDirectory);
        builder.UseSetting("Storage:UploadDirectory", Path.Combine(WorkDirectory, "uploads"));
        builder.UseSetting("Seed:Enabled", "true");

        builder.ConfigureTestServices(services =>
        {
            // Substitui o PostgreSQL pelo provider InMemory.
            services.RemoveAll<DbContextOptions<AppDbContext>>();
            services.AddDbContext<AppDbContext>(options => options.UseInMemoryDatabase(_databaseName));
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        // Defina SECURECORP_KEEP_TEST_FILES=1 para inspecionar os logs gerados pelos testes.
        if (disposing && Environment.GetEnvironmentVariable("SECURECORP_KEEP_TEST_FILES") != "1")
        {
            try
            {
                Directory.Delete(WorkDirectory, recursive: true);
            }
            catch (IOException)
            {
                // Arquivos de log ainda abertos: o diretório temporário será limpo pelo sistema.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
