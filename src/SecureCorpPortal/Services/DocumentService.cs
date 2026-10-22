using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;
using SecureCorpPortal.Repositories;

namespace SecureCorpPortal.Services;

public interface IDocumentService
{
    Task<IReadOnlyList<DocumentDto>> SearchAsync(CurrentUser user, string? term, CancellationToken cancellationToken = default);

    Task<ServiceResult<DocumentDto>> GetAsync(int id, CurrentUser user, CancellationToken cancellationToken = default);

    Task<ServiceResult<DocumentDto>> CreateAsync(CreateDocumentRequest request, CurrentUser user,
        CancellationToken cancellationToken = default);

    Task<ServiceResult<DocumentDto>> UploadAsync(UploadDocumentRequest request, CurrentUser user,
        CancellationToken cancellationToken = default);

    Task<ServiceResult<DocumentFile>> OpenFileAsync(int id, CurrentUser user, CancellationToken cancellationToken = default);

    Task<ServiceResult> DeleteAsync(int id, CurrentUser user, CancellationToken cancellationToken = default);
}

/// <summary>
/// Regras de documentos: listagem filtrada por permissão, leitura com auditoria,
/// criação (texto), upload (arquivo), download e exclusão.
/// As decisões de acesso ficam em DocumentAccessPolicy.
/// </summary>
public sealed class DocumentService : IDocumentService
{
    private const int MaxResults = 100;

    private readonly IDocumentRepository _documents;
    private readonly IFileStorageService _storage;
    private readonly IAuditService _audit;

    public DocumentService(IDocumentRepository documents, IFileStorageService storage, IAuditService audit)
    {
        _documents = documents;
        _storage = storage;
        _audit = audit;
    }

    public async Task<IReadOnlyList<DocumentDto>> SearchAsync(
        CurrentUser user, string? term, CancellationToken cancellationToken = default)
    {
        var results = await _documents.SearchVisibleAsync(
            DocumentAccessPolicy.VisibilityFor(user), term, MaxResults, cancellationToken);

        return results.Select(d => DtoMapper.ToDto(d, includeContent: false)).ToList();
    }

    public async Task<ServiceResult<DocumentDto>> GetAsync(int id, CurrentUser user, CancellationToken cancellationToken = default)
    {
        var document = await _documents.GetByIdAsync(id, cancellationToken);
        if (document is null)
        {
            return ServiceResult<DocumentDto>.Fail(ServiceStatus.NotFound, "Documento não encontrado.");
        }

        if (!DocumentAccessPolicy.CanRead(user, document))
        {
            await DenyAsync("document.read_denied", document, cancellationToken);
            return ServiceResult<DocumentDto>.Fail(ServiceStatus.Forbidden, "Você não tem permissão para este documento.");
        }

        await _audit.RecordAsync(new AuditEntry(AuditEventType.DocumentAccessed, "document.read")
        {
            Resource = $"document:{document.Id}",
            Details = $"Classificação {document.Classification}."
        }, cancellationToken);

        return ServiceResult<DocumentDto>.Ok(DtoMapper.ToDto(document, includeContent: true));
    }

    public async Task<ServiceResult<DocumentDto>> CreateAsync(
        CreateDocumentRequest request, CurrentUser user, CancellationToken cancellationToken = default)
    {
        if (!DocumentAccessPolicy.CanCreate(user, request.Classification))
        {
            await DenyCreateAsync(request.Classification, cancellationToken);
            return ServiceResult<DocumentDto>.Fail(ServiceStatus.Forbidden,
                "Seu papel não permite criar documentos com esta classificação.");
        }

        var document = new Document
        {
            Title = request.Title.Trim(),
            Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim(),
            Classification = request.Classification,
            Content = request.Content,
            OwnerId = user.Id,
            CreatedAt = DateTime.UtcNow
        };

        await _documents.AddAsync(document, cancellationToken);

        await _audit.RecordAsync(new AuditEntry(AuditEventType.DocumentCreated, "document.create")
        {
            Resource = $"document:{document.Id}",
            Details = $"Documento textual criado com classificação {document.Classification}."
        }, cancellationToken);

        return ServiceResult<DocumentDto>.Ok(await ReloadDtoAsync(document.Id, cancellationToken));
    }

    public async Task<ServiceResult<DocumentDto>> UploadAsync(
        UploadDocumentRequest request, CurrentUser user, CancellationToken cancellationToken = default)
    {
        if (!DocumentAccessPolicy.CanCreate(user, request.Classification))
        {
            await DenyCreateAsync(request.Classification, cancellationToken);
            return ServiceResult<DocumentDto>.Fail(ServiceStatus.Forbidden,
                "Seu papel não permite enviar documentos com esta classificação.");
        }

        var validation = _storage.Validate(request.File);
        if (!validation.IsValid)
        {
            await _audit.RecordAsync(new AuditEntry(AuditEventType.DocumentUploaded, "document.upload", Success: false)
            {
                Details = $"Upload rejeitado: {validation.Error} (extensão '{Path.GetExtension(request.File?.FileName ?? string.Empty)}', " +
                          $"{request.File?.Length ?? 0} bytes). Nome enviado pelo cliente: '{Truncate(request.File?.FileName)}'."
            }, cancellationToken);
            return ServiceResult<DocumentDto>.Fail(ServiceStatus.Invalid, validation.Error!);
        }

        var stored = await _storage.SaveAsync(request.File, cancellationToken);

        var document = new Document
        {
            Title = request.Title.Trim(),
            Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim(),
            Classification = request.Classification,
            OriginalFileName = stored.OriginalFileName,
            StoredFileName = stored.StoredFileName,
            ContentType = stored.ContentType,
            SizeBytes = stored.SizeBytes,
            OwnerId = user.Id,
            CreatedAt = DateTime.UtcNow
        };

        await _documents.AddAsync(document, cancellationToken);

        await _audit.RecordAsync(new AuditEntry(AuditEventType.DocumentUploaded, "document.upload")
        {
            Resource = $"document:{document.Id}",
            Details = $"Arquivo '{stored.OriginalFileName}' ({stored.SizeBytes} bytes, {stored.ContentType}), " +
                      $"classificação {document.Classification}." + SentNameNote(request.File.FileName, stored.OriginalFileName)
        }, cancellationToken);

        return ServiceResult<DocumentDto>.Ok(await ReloadDtoAsync(document.Id, cancellationToken));
    }

    public async Task<ServiceResult<DocumentFile>> OpenFileAsync(int id, CurrentUser user, CancellationToken cancellationToken = default)
    {
        var document = await _documents.GetByIdAsync(id, cancellationToken);
        if (document is null)
        {
            return ServiceResult<DocumentFile>.Fail(ServiceStatus.NotFound, "Documento não encontrado.");
        }

        if (!DocumentAccessPolicy.CanRead(user, document))
        {
            await DenyAsync("document.download_denied", document, cancellationToken);
            return ServiceResult<DocumentFile>.Fail(ServiceStatus.Forbidden, "Você não tem permissão para este documento.");
        }

        if (document.StoredFileName is null)
        {
            return ServiceResult<DocumentFile>.Fail(ServiceStatus.NotFound, "Este documento não possui arquivo.");
        }

        var stream = _storage.OpenRead(document.StoredFileName);
        if (stream is null)
        {
            return ServiceResult<DocumentFile>.Fail(ServiceStatus.NotFound, "Arquivo não encontrado no armazenamento.");
        }

        await _audit.RecordAsync(new AuditEntry(AuditEventType.DocumentDownloaded, "document.download")
        {
            Resource = $"document:{document.Id}",
            Details = $"Download de '{document.OriginalFileName}'."
        }, cancellationToken);

        return ServiceResult<DocumentFile>.Ok(new DocumentFile(
            stream,
            document.ContentType ?? "application/octet-stream",
            document.OriginalFileName ?? $"documento-{document.Id}"));
    }

    public async Task<ServiceResult> DeleteAsync(int id, CurrentUser user, CancellationToken cancellationToken = default)
    {
        var document = await _documents.GetByIdAsync(id, cancellationToken);
        if (document is null)
        {
            return ServiceResult.Fail(ServiceStatus.NotFound, "Documento não encontrado.");
        }

        if (!DocumentAccessPolicy.CanDelete(user, document))
        {
            await DenyAsync("document.delete_denied", document, cancellationToken);
            return ServiceResult.Fail(ServiceStatus.Forbidden, "Somente administradores podem excluir documentos.");
        }

        var storedFileName = document.StoredFileName;
        var title = document.Title;
        await _documents.DeleteAsync(document, cancellationToken);

        if (storedFileName is not null)
        {
            _storage.Delete(storedFileName);
        }

        await _audit.RecordAsync(new AuditEntry(AuditEventType.DocumentDeleted, "document.delete")
        {
            Resource = $"document:{id}",
            Details = $"Documento '{title}' excluído."
        }, cancellationToken);

        return ServiceResult.Ok();
    }

    /// <summary>
    /// O nome gravado é sanitizado (sem diretórios), o que esconderia tentativas de path traversal
    /// ("../../x"). Quando o nome enviado difere do gravado, o original vai para a auditoria.
    /// </summary>
    private static string SentNameNote(string? sentName, string storedName) =>
        sentName is null || sentName == storedName ? string.Empty : $" Nome enviado pelo cliente: '{Truncate(sentName)}'.";

    private static string Truncate(string? value, int max = 200) =>
        value is null ? string.Empty : value.Length <= max ? value : value[..max];

    private async Task<DocumentDto> ReloadDtoAsync(int id, CancellationToken cancellationToken)
    {
        var document = await _documents.GetByIdAsync(id, cancellationToken)
                       ?? throw new InvalidOperationException($"Documento {id} não encontrado após gravação.");
        return DtoMapper.ToDto(document, includeContent: true);
    }

    private Task DenyAsync(string action, Document document, CancellationToken cancellationToken) =>
        _audit.RecordAsync(new AuditEntry(AuditEventType.AccessDenied, action, Success: false)
        {
            Resource = $"document:{document.Id}",
            Details = $"Documento com classificação {document.Classification} acima do permitido para o papel."
        }, cancellationToken);

    private Task DenyCreateAsync(DocumentClassification classification, CancellationToken cancellationToken) =>
        _audit.RecordAsync(new AuditEntry(AuditEventType.AccessDenied, "document.create_denied", Success: false)
        {
            Details = $"Tentativa de criar documento com classificação {classification} acima do permitido."
        }, cancellationToken);
}
