using SecureCorpPortal.Logging;

namespace SecureCorpPortal.Lab;

/// <summary>Configuração do laboratório (seção "SecurityLab"). Desabilitado por padrão.</summary>
public sealed class SecurityLabOptions
{
    public const string SectionName = "SecurityLab";

    public bool Enabled { get; set; }

    /// <summary>Ids dos módulos a ativar (ex.: ["LAB-01"]). Vazio = nenhum.</summary>
    public List<string> EnabledModules { get; set; } = [];
}

/// <summary>Catálogo exposto à área administrativa (status do laboratório).</summary>
public sealed class LabModuleCatalog
{
    public LabModuleCatalog(bool enabled, IReadOnlyList<ILabModule> available, IReadOnlyList<ILabModule> active)
    {
        Enabled = enabled;
        Available = available;
        Active = active;
    }

    public bool Enabled { get; }

    public IReadOnlyList<ILabModule> Available { get; }

    public IReadOnlyList<ILabModule> Active { get; }
}

/// <summary>
/// Ponto único de conexão dos módulos de laboratório com a aplicação.
/// Para adicionar um módulo no futuro:
///   1. criar a classe em Lab/Modules/ implementando ILabModule;
///   2. incluí-la em AvailableModules abaixo;
///   3. habilitar via SecurityLab:Enabled=true e SecurityLab:EnabledModules.
/// </summary>
public static class SecurityLabExtensions
{
    /// <summary>Lista explícita de módulos disponíveis. Vazia nesta primeira etapa.</summary>
    private static readonly ILabModule[] AvailableModules = [];

    public static IServiceCollection AddSecurityLab(this IServiceCollection services, IConfiguration configuration)
    {
        var options = configuration.GetSection(SecurityLabOptions.SectionName).Get<SecurityLabOptions>()
                      ?? new SecurityLabOptions();

        var active = options.Enabled
            ? AvailableModules
                .Where(m => options.EnabledModules.Contains(m.Id, StringComparer.OrdinalIgnoreCase))
                .ToList()
            : [];

        foreach (var module in active)
        {
            module.ConfigureServices(services);
        }

        services.AddSingleton(new LabModuleCatalog(options.Enabled, AvailableModules, active));
        return services;
    }

    public static WebApplication MapSecurityLab(this WebApplication app)
    {
        var catalog = app.Services.GetRequiredService<LabModuleCatalog>();
        if (!catalog.Enabled)
        {
            return app;
        }

        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("SecureCorpPortal.Lab");
        using (logger.BeginEventScope("SecurityLabEnabled", EventCategories.Security, severity: "high"))
        {
            logger.LogWarning("Laboratório de segurança HABILITADO com {module_count} módulo(s) ativo(s): {modules}",
                catalog.Active.Count, string.Join(", ", catalog.Active.Select(m => m.Id)));
        }

        foreach (var module in catalog.Active)
        {
            module.MapEndpoints(app);
        }

        return app;
    }
}
