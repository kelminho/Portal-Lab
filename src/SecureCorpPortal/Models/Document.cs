namespace SecureCorpPortal.Models;

/// <summary>
/// Documento corporativo. Pode ser apenas texto (Content) ou ter um arquivo
/// associado (StoredFileName). Tabela: documents.
/// </summary>
public class Document
{
    public int Id { get; set; }

    public string Title { get; set; } = string.Empty;

    public string? Description { get; set; }

    /// <summary>Nível de sigilo; define quais papéis podem ler o documento.</summary>
    public DocumentClassification Classification { get; set; } = DocumentClassification.Internal;

    /// <summary>Conteúdo textual (documentos criados sem arquivo).</summary>
    public string? Content { get; set; }

    /// <summary>Nome original enviado pelo usuário (apenas para exibição/download).</summary>
    public string? OriginalFileName { get; set; }

    /// <summary>Nome aleatório gerado pelo servidor para o arquivo em disco.</summary>
    public string? StoredFileName { get; set; }

    public string? ContentType { get; set; }

    public long? SizeBytes { get; set; }

    /// <summary>Dono do documento. Fica nulo se o usuário for excluído (ON DELETE SET NULL).</summary>
    public int? OwnerId { get; set; }

    public ApplicationUser? Owner { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    public bool HasFile => StoredFileName is not null;
}
