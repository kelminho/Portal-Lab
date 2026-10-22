using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Logging;

namespace SecureCorpPortal.Data;

/// <summary>
/// Executado uma vez na inicialização:
/// 1. aplica as migrations pendentes (PostgreSQL) — com novas tentativas, pois no
///    Docker o banco pode ainda estar subindo;
/// 2. executa o seed de demonstração se Seed:Enabled=true.
/// Em testes (provider InMemory, não relacional) usa EnsureCreated.
/// </summary>
public static class DatabaseInitializer
{
    private const int MaxAttempts = 10;
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(3);

    public static async Task InitializeDatabaseAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var services = scope.ServiceProvider;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(DatabaseInitializer).FullName!);
        var db = services.GetRequiredService<AppDbContext>();

        using (logger.BeginEventScope(TechnicalEventTypes.DatabaseInitialization, EventCategories.Application))
        {
            if (db.Database.IsRelational())
            {
                await MigrateWithRetryAsync(db, logger);
            }
            else
            {
                await db.Database.EnsureCreatedAsync();
            }

            var seedOptions = services.GetRequiredService<IOptions<SeedOptions>>().Value;
            if (seedOptions.Enabled)
            {
                await services.GetRequiredService<DatabaseSeeder>().SeedAsync();
                logger.LogWarning("Dados de demonstração habilitados (Seed:Enabled=true). Use somente em laboratório.");
            }
            else
            {
                logger.LogInformation("Seed de demonstração desabilitado (Seed:Enabled=false).");
            }
        }
    }

    private static async Task MigrateWithRetryAsync(AppDbContext db, ILogger logger)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await db.Database.MigrateAsync();
                logger.LogInformation("Migrations aplicadas com sucesso");
                return;
            }
            catch (Exception ex) when (attempt < MaxAttempts)
            {
                logger.LogWarning(ex, "Banco indisponível (tentativa {attempt}/{max}). Nova tentativa em {delay}s",
                    attempt, MaxAttempts, RetryDelay.TotalSeconds);
                await Task.Delay(RetryDelay);
            }
        }
    }
}
