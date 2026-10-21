using System.ComponentModel.DataAnnotations;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.DTOs;

/// <summary>
/// Documento retornado pela API. StoredFileName (nome interno em disco) nunca é exposto.
/// Em listagens, Content vem nulo para reduzir a exposição de dados.
/// </summary>
public sealed record DocumentDto(
    int Id,
    string Title,
    string? Description,
    DocumentClassification Classification,
    string? Content,
    bool HasFile,
    string? OriginalFileName,
    string? ContentType,
    long? SizeBytes,
    int? OwnerId,
    string? OwnerName,
    DateTime CreatedAt,
    DateTime? UpdatedAt);

/// <summary>Criação de documento textual (POST /api/documents, JSON).</summary>
public sealed class CreateDocumentRequest
{
    [Required, StringLength(200, MinimumLength = 3)]
    public string Title { get; set; } = string.Empty;

    [StringLength(1000)]
    public string? Description { get; set; }

    public DocumentClassification Classification { get; set; } = DocumentClassification.Internal;

    [Required, StringLength(20000, MinimumLength = 1)]
    public string Content { get; set; } = string.Empty;
}

/// <summary>Upload de arquivo (POST /api/documents/upload, multipart/form-data).</summary>
public sealed class UploadDocumentRequest
{
    [Required, StringLength(200, MinimumLength = 3)]
    public string Title { get; set; } = string.Empty;

    [StringLength(1000)]
    public string? Description { get; set; }

    public DocumentClassification Classification { get; set; } = DocumentClassification.Internal;

    [Required]
    public IFormFile File { get; set; } = null!;
}

/// <summary>Arquivo pronto para download (stream + metadados seguros).</summary>
public sealed record DocumentFile(Stream Content, string ContentType, string DownloadName);
