using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Lab;

namespace SecureCorpPortal.Models.ViewModels;

public sealed class DocumentListViewModel
{
    public string? Query { get; init; }

    public IReadOnlyList<DocumentDto> Documents { get; init; } = [];

    public bool CanCreate { get; init; }
}

public sealed class DocumentDetailsViewModel
{
    public required DocumentDto Document { get; init; }

    public bool CanDelete { get; init; }
}

public sealed class DocumentUploadViewModel
{
    [Required(ErrorMessage = "Informe o título.")]
    [StringLength(200, MinimumLength = 3, ErrorMessage = "O título deve ter entre 3 e 200 caracteres.")]
    [Display(Name = "Título")]
    public string Title { get; set; } = string.Empty;

    [StringLength(1000)]
    [Display(Name = "Descrição")]
    public string? Description { get; set; }

    [Display(Name = "Classificação")]
    public DocumentClassification Classification { get; set; } = DocumentClassification.Internal;

    [StringLength(20000)]
    [Display(Name = "Conteúdo (texto)")]
    public string? Content { get; set; }

    [Display(Name = "Arquivo")]
    public IFormFile? File { get; set; }

    // Dados auxiliares para a view: [BindNever] impede que venham do formulário.
    [BindNever]
    public IEnumerable<SelectListItem> ClassificationOptions { get; set; } = [];

    [BindNever]
    public IReadOnlyList<string> AllowedExtensions { get; set; } = [];

    [BindNever]
    public long MaxFileSizeBytes { get; set; }
}

public sealed class UserDirectoryViewModel
{
    public string? Query { get; init; }

    public IReadOnlyList<UserDto> Users { get; init; } = [];
}

public sealed class SearchViewModel
{
    public string? Query { get; init; }

    public bool CanSearchUsers { get; init; }

    public IReadOnlyList<DocumentDto> Documents { get; init; } = [];

    public IReadOnlyList<UserDto> Users { get; init; } = [];

    public bool HasQuery => !string.IsNullOrWhiteSpace(Query);
}

public sealed class AdminIndexViewModel
{
    public required DashboardDto Dashboard { get; init; }

    public required LabModuleCatalog Lab { get; init; }
}

public sealed class AdminEditUserViewModel
{
    public int Id { get; set; }

    public string UserName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Informe o nome completo.")]
    [StringLength(100)]
    [Display(Name = "Nome completo")]
    public string FullName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Informe o e-mail.")]
    [EmailAddress(ErrorMessage = "E-mail inválido.")]
    [Display(Name = "E-mail")]
    public string Email { get; set; } = string.Empty;

    [StringLength(100)]
    [Display(Name = "Departamento")]
    public string? Department { get; set; }

    [StringLength(100)]
    [Display(Name = "Cargo")]
    public string? JobTitle { get; set; }

    [Display(Name = "Papel")]
    public string Role { get; set; } = string.Empty;

    [Display(Name = "Conta ativa")]
    public bool IsActive { get; set; }

    [BindNever]
    public bool IsSelf { get; set; }

    [BindNever]
    public IEnumerable<SelectListItem> RoleOptions { get; set; } = [];
}

public sealed class AuditLogViewModel
{
    public required AuditQuery Query { get; init; }

    public required PagedResult<AuditEventDto> Result { get; init; }

    /// <summary>Parâmetros de rota para os links de paginação, preservando os filtros.</summary>
    public Dictionary<string, string> RouteForPage(int page)
    {
        var route = new Dictionary<string, string>
        {
            ["page"] = page.ToString(),
            ["pageSize"] = Query.PageSize.ToString()
        };

        if (Query.EventType is not null) route["eventType"] = Query.EventType.ToString()!;
        if (Query.Severity is not null) route["severity"] = Query.Severity.ToString()!;
        if (!string.IsNullOrWhiteSpace(Query.Username)) route["username"] = Query.Username;
        if (Query.Success is not null) route["success"] = Query.Success.Value.ToString().ToLowerInvariant();
        if (Query.From is not null) route["from"] = Query.From.Value.ToString("yyyy-MM-ddTHH:mm");
        if (Query.To is not null) route["to"] = Query.To.Value.ToString("yyyy-MM-ddTHH:mm");

        return route;
    }
}

public sealed class ErrorViewModel
{
    public int StatusCode { get; init; } = 500;

    public string? RequestId { get; init; }

    public string Title => StatusCode switch
    {
        400 => "Requisição inválida",
        403 => "Acesso negado",
        404 => "Página não encontrada",
        _ => "Erro inesperado"
    };

    public string Message => StatusCode switch
    {
        400 => "A requisição não pôde ser processada. Verifique os dados e tente novamente.",
        403 => "Você não tem permissão para acessar este recurso. A tentativa foi registrada.",
        404 => "O recurso solicitado não existe ou foi removido.",
        _ => "Ocorreu um erro ao processar sua solicitação. Se o problema persistir, informe o código abaixo ao suporte."
    };
}
