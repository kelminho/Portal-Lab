using Microsoft.EntityFrameworkCore;
using SecureCorpPortal.Data;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.Repositories;

/// <summary>
/// Acesso a dados de documentos. Toda consulta usa LINQ (parametrizado pelo EF Core),
/// nunca SQL concatenado.
/// </summary>
public sealed class DocumentRepository : IDocumentRepository
{
    private readonly AppDbContext _db;

    public DocumentRepository(AppDbContext db)
    {
        _db = db;
    }

    public Task<Document?> GetByIdAsync(int id, CancellationToken cancellationToken = default) =>
        _db.Documents
            .Include(d => d.Owner)
            .FirstOrDefaultAsync(d => d.Id == id, cancellationToken);

    public async Task<IReadOnlyList<Document>> SearchVisibleAsync(
        DocumentVisibility visibility, string? term, int take, CancellationToken cancellationToken = default)
    {
        var query = Visible(visibility).Include(d => d.Owner).AsNoTracking();

        if (!string.IsNullOrWhiteSpace(term))
        {
            var normalized = term.Trim().ToLower();
            query = query.Where(d =>
                d.Title.ToLower().Contains(normalized) ||
                (d.Description != null && d.Description.ToLower().Contains(normalized)));
        }

        return await query
            .OrderByDescending(d => d.CreatedAt)
            .Take(take)
            .ToListAsync(cancellationToken);
    }

    public Task<int> CountVisibleAsync(DocumentVisibility visibility, CancellationToken cancellationToken = default) =>
        Visible(visibility).CountAsync(cancellationToken);

    public Task<int> CountOwnedByAsync(int ownerId, CancellationToken cancellationToken = default) =>
        _db.Documents.CountAsync(d => d.OwnerId == ownerId, cancellationToken);

    public async Task<IReadOnlyDictionary<DocumentClassification, int>> CountByClassificationAsync(
        CancellationToken cancellationToken = default)
    {
        var rows = await _db.Documents
            .GroupBy(d => d.Classification)
            .Select(g => new { Classification = g.Key, Count = g.Count() })
            .ToListAsync(cancellationToken);

        return rows.ToDictionary(r => r.Classification, r => r.Count);
    }

    public async Task AddAsync(Document document, CancellationToken cancellationToken = default)
    {
        _db.Documents.Add(document);
        await _db.SaveChangesAsync(cancellationToken);
    }

    public async Task DeleteAsync(Document document, CancellationToken cancellationToken = default)
    {
        _db.Documents.Remove(document);
        await _db.SaveChangesAsync(cancellationToken);
    }

    private IQueryable<Document> Visible(DocumentVisibility visibility)
    {
        var allowed = visibility.Classifications.ToList();
        var userId = visibility.UserId;
        return _db.Documents.Where(d => allowed.Contains(d.Classification) || d.OwnerId == userId);
    }
}
