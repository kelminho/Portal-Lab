using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureCorpPortal.Data;
using SecureCorpPortal.Models;
using SecureCorpPortal.Repositories;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Configuration;

/// <summary>
/// Agrupa o registro de serviços para manter o Program.cs curto e legível.
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddPortalOptions(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<StorageOptions>(configuration.GetSection(StorageOptions.SectionName));
        services.Configure<SeedOptions>(configuration.GetSection(SeedOptions.SectionName));
        services.Configure<AppLoggingOptions>(configuration.GetSection(AppLoggingOptions.SectionName));
        return services;
    }

    public static IServiceCollection AddPortalDatabase(this IServiceCollection services)
    {
        services.AddDbContext<AppDbContext>((serviceProvider, options) =>
        {
            var connectionString = serviceProvider
                .GetRequiredService<IConfiguration>()
                .GetConnectionString("DefaultConnection");

            if (string.IsNullOrWhiteSpace(connectionString))
            {
                throw new InvalidOperationException(
                    "ConnectionStrings:DefaultConnection não configurada. " +
                    "Use appsettings.Development.json ou a variável ConnectionStrings__DefaultConnection.");
            }

            options.UseNpgsql(connectionString);
        });

        return services;
    }

    public static IServiceCollection AddPortalIdentity(this IServiceCollection services)
    {
        services
            .AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                // Política de senha
                options.Password.RequiredLength = 8;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;

                // Bloqueio após tentativas falhas (proteção contra força bruta)
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.AllowedForNewUsers = true;

                options.User.RequireUniqueEmail = true;
                options.SignIn.RequireConfirmedAccount = false;
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddErrorDescriber<PortugueseIdentityErrorDescriber>()
            .AddDefaultTokenProviders();

        // Revalida o "security stamp" do cookie a cada minuto: quando um admin muda
        // o papel ou desativa um usuário, a sessão antiga deixa de valer rapidamente.
        services.Configure<SecurityStampValidatorOptions>(options =>
            options.ValidationInterval = TimeSpan.FromMinutes(1));

        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.Name = "SecureCorp.Auth";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            // O laboratório roda em HTTP local. Em produção use CookieSecurePolicy.Always + HTTPS.
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
            options.SlidingExpiration = true;
            options.LoginPath = "/login";
            options.LogoutPath = "/logout";
            options.AccessDeniedPath = "/access-denied";
            options.Events.OnRedirectToLogin = AuthenticationEventHandlers.OnRedirectToLogin;
            options.Events.OnRedirectToAccessDenied = AuthenticationEventHandlers.OnRedirectToAccessDenied;
        });

        services.AddAntiforgery(options =>
        {
            options.Cookie.Name = "SecureCorp.Csrf";
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.HttpOnly = true;
        });

        services.AddAuthorization(options => options.AddPortalPolicies());

        return services;
    }

    /// <summary>
    /// Persiste as chaves de Data Protection (usadas para cifrar cookies) quando
    /// DataProtection:KeysDirectory estiver configurado — no Docker, isso evita que
    /// todos os usuários sejam deslogados a cada reinício do container.
    /// </summary>
    public static IServiceCollection AddPortalDataProtection(
        this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        var dataProtection = services.AddDataProtection().SetApplicationName("SecureCorpPortal");

        var keysDirectory = configuration["DataProtection:KeysDirectory"];
        if (!string.IsNullOrWhiteSpace(keysDirectory))
        {
            var fullPath = Path.GetFullPath(Path.Combine(environment.ContentRootPath, keysDirectory));
            dataProtection.PersistKeysToFileSystem(new DirectoryInfo(fullPath));
        }

        return services;
    }

    public static IServiceCollection AddPortalApplicationServices(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();

        // Repositories (acesso a dados)
        services.AddScoped<IDocumentRepository, DocumentRepository>();
        services.AddScoped<IAuditEventRepository, AuditEventRepository>();

        // Services (regras de negócio)
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IUserService, UserService>();
        services.AddScoped<IDocumentService, DocumentService>();
        services.AddScoped<IFileStorageService, LocalFileStorageService>();
        services.AddScoped<IDashboardService, DashboardService>();

        // Dados iniciais
        services.AddScoped<DatabaseSeeder>();

        return services;
    }
}
