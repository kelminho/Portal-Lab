using System.Text.Encodings.Web;
using System.Text.Json.Serialization;
using System.Text.Unicode;
using Microsoft.Extensions.WebEncoders;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Data;
using SecureCorpPortal.Lab;
using SecureCorpPortal.Logging;
using SecureCorpPortal.Middleware;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// 1. Logging estruturado: Serilog -> JSON em /logs (ver Logging/SerilogSetup.cs).
//    A configuração é lida a partir do IServiceProvider para respeitar
//    sobrescritas feitas por variáveis de ambiente e pelos testes.
//    preserveStaticLogger: true -> cada host usa sua PRÓPRIA instância de logger
//    (e não o Log.Logger estático), o que mantém testes paralelos isolados.
// ---------------------------------------------------------------------------
builder.Services.AddSerilog(
    (services, loggerConfiguration) => loggerConfiguration.ConfigurePortalLogging(
        services.GetRequiredService<IConfiguration>(),
        services.GetRequiredService<IHostEnvironment>()),
    preserveStaticLogger: true);

// ---------------------------------------------------------------------------
// 2. Opções, banco de dados, Identity, autorização e serviços da aplicação
//    (ver Configuration/ServiceCollectionExtensions.cs).
// ---------------------------------------------------------------------------
builder.Services.AddPortalOptions(builder.Configuration);
builder.Services.AddPortalForwardedHeaders(builder.Configuration);
builder.Services.AddPortalDatabase();
builder.Services.AddPortalIdentity();
builder.Services.AddPortalDataProtection(builder.Configuration, builder.Environment);
builder.Services.AddPortalApplicationServices();

// 3. Ponto de extensão para o futuro laboratório de segurança.
//    Desabilitado por padrão e sem nenhum módulo implementado nesta etapa.
builder.Services.AddSecurityLab(builder.Configuration);

// 4. MVC (Razor Views) + API REST no mesmo projeto.
builder.Services
    .AddControllersWithViews(options => options.Filters.Add<AntiforgeryFailureAuditFilter>())
    .AddJsonOptions(options =>
        options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));

// Razor continua codificando <, >, &, " (proteção contra XSS), mas deixa
// acentos legíveis no HTML ("é" em vez de "&#xE9;").
builder.Services.Configure<WebEncoderOptions>(options =>
    options.TextEncoderSettings = new TextEncoderSettings(UnicodeRanges.All));

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddHealthChecks();

var app = builder.Build();

// ---------------------------------------------------------------------------
// Pipeline HTTP — a ORDEM dos middlewares importa.
// Ver docs/architecture/request-flow.md para a explicação de cada etapa.
// ---------------------------------------------------------------------------
app.UsePortalForwardedHeaders();                     // IP real atrás de proxy (opt-in, só redes confiáveis)
app.UseMiddleware<CorrelationMiddleware>();          // request_id + contexto de log
app.UseExceptionHandler("/error");                   // exceções -> log + resposta genérica
app.UseStatusCodePagesWithReExecute("/error/{0}");   // páginas amigáveis para 403/404
app.UseMiddleware<SecurityHeadersMiddleware>();      // CSP, X-Frame-Options, ...
app.UseStaticFiles();                                // wwwroot (css/js)
app.UseRouting();
app.UseAuthentication();                             // lê o cookie e popula HttpContext.User
app.UseMiddleware<RequestLoggingMiddleware>();       // 1 evento JSON por requisição
app.UseAuthorization();                              // aplica [Authorize] e policies

app.MapControllers();
app.MapHealthChecks("/health").AllowAnonymous();
app.MapSecurityLab();

// Aplica migrations e (opcionalmente) cria os dados de demonstração.
await app.InitializeDatabaseAsync();

app.Run();

/// <summary>
/// Declaração parcial necessária para que WebApplicationFactory&lt;Program&gt;
/// consiga iniciar a aplicação nos testes de integração.
/// </summary>
public partial class Program { }
