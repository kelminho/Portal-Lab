using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.Data;

/// <summary>
/// Cria os dados iniciais do laboratório (papéis, usuários e documentos).
///
/// Por que não usar HasData() nas migrations? Usuários precisam de hash de senha,
/// security stamp e campos normalizados gerados pelo Identity. Usar UserManager
/// em tempo de execução é mais simples e correto. O seed é idempotente: só cria
/// o que ainda não existe.
/// </summary>
public sealed class DatabaseSeeder
{
    private static readonly (string Name, string Description)[] RoleDefinitions =
    [
        (AppRoles.Admin, AppRoles.Describe(AppRoles.Admin)),
        (AppRoles.Analyst, AppRoles.Describe(AppRoles.Analyst)),
        (AppRoles.Employee, AppRoles.Describe(AppRoles.Employee)),
        (AppRoles.Guest, AppRoles.Describe(AppRoles.Guest))
    ];

    private readonly AppDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly ILogger<DatabaseSeeder> _logger;

    public DatabaseSeeder(
        AppDbContext db,
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        ILogger<DatabaseSeeder> logger)
    {
        _db = db;
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
    }

    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        await SeedRolesAsync();
        await SeedUsersAsync();
        await SeedDocumentsAsync(cancellationToken);
    }

    private async Task SeedRolesAsync()
    {
        foreach (var (name, description) in RoleDefinitions)
        {
            if (await _roleManager.RoleExistsAsync(name))
            {
                continue;
            }

            var result = await _roleManager.CreateAsync(new ApplicationRole(name, description));
            EnsureSucceeded(result, $"criar papel {name}");
            _logger.LogInformation("Seed: papel {role} criado", name);
        }
    }

    private async Task SeedUsersAsync()
    {
        foreach (var account in DemoAccounts.All)
        {
            if (await _userManager.FindByNameAsync(account.UserName) is not null)
            {
                continue;
            }

            var user = new ApplicationUser
            {
                UserName = account.UserName,
                Email = account.Email,
                EmailConfirmed = true,
                FullName = account.FullName,
                Department = account.Department,
                JobTitle = account.JobTitle,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            EnsureSucceeded(await _userManager.CreateAsync(user, account.Password), $"criar usuário {account.UserName}");
            EnsureSucceeded(await _userManager.AddToRoleAsync(user, account.Role), $"atribuir papel a {account.UserName}");

            _logger.LogInformation("Seed: usuário de demonstração {username} criado com papel {role}",
                account.UserName, account.Role);
        }
    }

    private async Task SeedDocumentsAsync(CancellationToken cancellationToken)
    {
        if (await _db.Documents.AnyAsync(cancellationToken))
        {
            return;
        }

        var owners = await _db.Users
            .Where(u => u.UserName != null)
            .ToDictionaryAsync(u => u.UserName!, u => u.Id, cancellationToken);

        int? Owner(DemoAccounts.DemoAccount account) =>
            owners.TryGetValue(account.UserName, out var id) ? id : null;

        var now = DateTime.UtcNow;

        var documents = new List<Document>
        {
            new()
            {
                Title = "Política de Uso Aceitável",
                Description = "Regras gerais para uso de recursos de TI da SecureCorp.",
                Classification = DocumentClassification.Public,
                Content = "Todos os colaboradores devem utilizar os recursos de TI de forma ética e responsável. " +
                          "É proibido compartilhar credenciais. Incidentes devem ser reportados ao time de Segurança.",
                OwnerId = Owner(DemoAccounts.Admin),
                CreatedAt = now.AddDays(-120)
            },
            new()
            {
                Title = "Manual do Colaborador",
                Description = "Benefícios, horários e canais de atendimento do RH.",
                Classification = DocumentClassification.Public,
                Content = "Bem-vindo à SecureCorp! Este manual reúne as principais informações sobre benefícios, " +
                          "jornada de trabalho e canais de comunicação com o RH.",
                OwnerId = Owner(DemoAccounts.HumanResources),
                CreatedAt = now.AddDays(-90)
            },
            new()
            {
                Title = "Calendário de Feriados",
                Description = "Feriados nacionais e pontos facultativos do ano.",
                Classification = DocumentClassification.Public,
                Content = "01/01 Confraternização Universal; 21/04 Tiradentes; 01/05 Dia do Trabalho; " +
                          "07/09 Independência; 12/10 N. Sra. Aparecida; 02/11 Finados; 15/11 Proclamação da República; 25/12 Natal.",
                OwnerId = Owner(DemoAccounts.HumanResources),
                CreatedAt = now.AddDays(-60)
            },
            new()
            {
                Title = "Procedimento de Reembolso de Despesas",
                Description = "Fluxo interno para solicitação de reembolso.",
                Classification = DocumentClassification.Internal,
                Content = "1. Registre a despesa no sistema financeiro. 2. Anexe o comprovante. " +
                          "3. Aguarde aprovação do gestor. 4. O pagamento ocorre no ciclo quinzenal seguinte.",
                OwnerId = Owner(DemoAccounts.Employee),
                CreatedAt = now.AddDays(-45)
            },
            new()
            {
                Title = "Organograma Interno",
                Description = "Estrutura das diretorias e gerências.",
                Classification = DocumentClassification.Internal,
                Content = "Diretoria Executiva > Tecnologia, Financeiro, Comercial, Recursos Humanos, Segurança da Informação.",
                OwnerId = Owner(DemoAccounts.Admin),
                CreatedAt = now.AddDays(-40)
            },
            new()
            {
                Title = "Metas Comerciais do Trimestre",
                Description = "Objetivos de vendas por região.",
                Classification = DocumentClassification.Internal,
                Content = "Sudeste: 40% da meta global. Sul: 25%. Nordeste: 20%. Demais regiões: 15%.",
                OwnerId = Owner(DemoAccounts.Sales),
                CreatedAt = now.AddDays(-20)
            },
            new()
            {
                Title = "Relatório de Incidentes de Segurança",
                Description = "Consolidado trimestral de incidentes tratados pelo SOC.",
                Classification = DocumentClassification.Confidential,
                Content = "Foram tratados 14 incidentes no trimestre: 9 phishing, 3 malware bloqueado em endpoint, " +
                          "2 tentativas de acesso não autorizado. Nenhum vazamento de dados confirmado.",
                OwnerId = Owner(DemoAccounts.Analyst),
                CreatedAt = now.AddDays(-15)
            },
            new()
            {
                Title = "Plano de Resposta a Incidentes",
                Description = "Papéis, responsabilidades e fluxo de escalonamento.",
                Classification = DocumentClassification.Confidential,
                Content = "Fases: Preparação, Identificação, Contenção, Erradicação, Recuperação e Lições Aprendidas. " +
                          "O analista de plantão aciona o coordenador de segurança em incidentes de severidade alta.",
                OwnerId = Owner(DemoAccounts.Analyst),
                CreatedAt = now.AddDays(-10)
            },
            new()
            {
                Title = "Resumo da Folha de Pagamento",
                Description = "Totais consolidados por departamento.",
                Classification = DocumentClassification.Restricted,
                Content = "Documento restrito à diretoria. Valores fictícios para fins de laboratório.",
                OwnerId = Owner(DemoAccounts.Admin),
                CreatedAt = now.AddDays(-5)
            },
            new()
            {
                Title = "Plano Estratégico",
                Description = "Iniciativas estratégicas para os próximos dois anos.",
                Classification = DocumentClassification.Restricted,
                Content = "Expansão para novos mercados, modernização da plataforma e programa de conscientização em segurança.",
                OwnerId = Owner(DemoAccounts.Admin),
                CreatedAt = now.AddDays(-2)
            }
        };

        _db.Documents.AddRange(documents);
        await _db.SaveChangesAsync(cancellationToken);
        _logger.LogInformation("Seed: {count} documentos de demonstração criados", documents.Count);
    }

    private static void EnsureSucceeded(IdentityResult result, string operation)
    {
        if (!result.Succeeded)
        {
            var errors = string.Join("; ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Falha no seed ao {operation}: {errors}");
        }
    }
}
