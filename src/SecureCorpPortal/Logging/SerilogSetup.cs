using SecureCorpPortal.Configuration;
using Serilog;
using Serilog.Filters;

namespace SecureCorpPortal.Logging;

/// <summary>
/// Configuração central do Serilog.
///
/// Destinos:
///   logs/securecorp-AAAAMMDD.json  todos os eventos (JSON Lines)
///   logs/security-AAAAMMDD.json    somente event_category = audit | security
///   console                        texto legível (ou JSON, se AppLogging:ConsoleFormat=json)
///
/// Níveis mínimos por namespace ficam em appsettings.json, seção "Serilog".
/// </summary>
public static class SerilogSetup
{
    public const string MainLogFilePattern = "securecorp-.json";
    public const string SecurityLogFilePattern = "security-.json";

    public static LoggerConfiguration ConfigurePortalLogging(
        this LoggerConfiguration loggerConfiguration,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var options = configuration.GetSection(AppLoggingOptions.SectionName).Get<AppLoggingOptions>()
                      ?? new AppLoggingOptions();

        var logDirectory = ResolveLogDirectory(options.Directory, environment.ContentRootPath);
        Directory.CreateDirectory(logDirectory);

        var formatter = new SiemJsonFormatter("SecureCorpPortal", environment.EnvironmentName, Environment.MachineName);

        loggerConfiguration
            .ReadFrom.Configuration(configuration)
            .Enrich.FromLogContext()
            .WriteTo.File(
                formatter,
                Path.Combine(logDirectory, MainLogFilePattern),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: options.RetainedFileCountLimit)
            .WriteTo.Logger(security => security
                .Filter.ByIncludingOnly(Matching.WithProperty<string>(
                    LogFields.EventCategory,
                    category => category is EventCategories.Audit or EventCategories.Security))
                .WriteTo.File(
                    formatter,
                    Path.Combine(logDirectory, SecurityLogFilePattern),
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: options.RetainedFileCountLimit));

        if (string.Equals(options.ConsoleFormat, "json", StringComparison.OrdinalIgnoreCase))
        {
            loggerConfiguration.WriteTo.Console(formatter);
        }
        else
        {
            loggerConfiguration.WriteTo.Console(
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}");
        }

        return loggerConfiguration;
    }

    public static string ResolveLogDirectory(string directory, string contentRootPath) =>
        Path.GetFullPath(Path.Combine(contentRootPath, directory));
}
