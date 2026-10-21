using SecureCorpPortal.Models;

namespace SecureCorpPortal.Repositories;

/// <summary>
/// Define quais documentos um usuário enxerga: os das classificações permitidas
/// ao seu papel OU aqueles dos quais ele é dono.
/// </summary>
public sealed record DocumentVisibility(int UserId, IReadOnlyCollection<DocumentClassification> Classifications);

public interface IDocumentRepository
{
    Task<Document?> GetByIdAsync(int id, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Document>> SearchVisibleAsync(
        DocumentVisibility visibility, string? term, int take, CancellationToken cancellationToken = default);

    Task<int> CountVisibleAsync(DocumentVisibility visibility, CancellationToken cancellationToken = default);

    Task<int> CountOwnedByAsync(int ownerId, CancellationToken cancellationToken = default);

    Task<IReadOnlyDictionary<DocumentClassification, int>> CountByClassificationAsync(
        CancellationToken cancellationToken = default);

    Task AddAsync(Document document, CancellationToken cancellationToken = default);

    Task DeleteAsync(Document document, CancellationToken cancellationToken = default);
}
