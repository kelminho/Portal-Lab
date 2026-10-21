using Microsoft.AspNetCore.Authorization;

namespace SecureCorpPortal.Configuration;

/// <summary>
/// Policies de autorização. Os controllers referenciam policies (o "quê")
/// em vez de papéis (o "quem"), o que facilita mudar regras em um único lugar.
/// </summary>
public static class Policies
{
    public const string AdminOnly = nameof(AdminOnly);
    public const string CanViewUserDirectory = nameof(CanViewUserDirectory);
    public const string CanCreateDocuments = nameof(CanCreateDocuments);
    public const string CanViewSecurityAnalytics = nameof(CanViewSecurityAnalytics);

    public static void AddPortalPolicies(this AuthorizationOptions options)
    {
        options.AddPolicy(AdminOnly, policy => policy
            .RequireAuthenticatedUser()
            .RequireRole(AppRoles.Admin));

        options.AddPolicy(CanViewUserDirectory, policy => policy
            .RequireAuthenticatedUser()
            .RequireRole(AppRoles.Admin, AppRoles.Analyst));

        options.AddPolicy(CanCreateDocuments, policy => policy
            .RequireAuthenticatedUser()
            .RequireRole(AppRoles.Admin, AppRoles.Analyst, AppRoles.Employee));

        options.AddPolicy(CanViewSecurityAnalytics, policy => policy
            .RequireAuthenticatedUser()
            .RequireRole(AppRoles.Admin, AppRoles.Analyst));

        // "Seguro por padrão": qualquer endpoint sem [Authorize]/[AllowAnonymous]
        // exige um usuário autenticado.
        options.FallbackPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
    }
}
