using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Options;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models.ViewModels;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers;

/// <summary>Páginas de documentos: listagem/busca, detalhes, download, upload e exclusão.</summary>
[Authorize]
public class DocumentsController : PortalControllerBase
{
    private readonly IDocumentService _documents;
    private readonly IAuthorizationService _authorization;
    private readonly StorageOptions _storageOptions;

    public DocumentsController(
        IDocumentService documents,
        IAuthorizationService authorization,
        IOptions<StorageOptions> storageOptions)
    {
        _documents = documents;
        _authorization = authorization;
        _storageOptions = storageOptions.Value;
    }

    [HttpGet("/documents")]
    public async Task<IActionResult> Index(string? q, CancellationToken cancellationToken)
    {
        var query = q?.Trim();
        if (query?.Length > 100)
        {
            query = query[..100];
        }

        var canCreate = (await _authorization.AuthorizeAsync(User, Policies.CanCreateDocuments)).Succeeded;
        var documents = await _documents.SearchAsync(CurrentUser, query, cancellationToken);

        return View(new DocumentListViewModel { Query = query, Documents = documents, CanCreate = canCreate });
    }

    [HttpGet("/documents/{id:int}")]
    public async Task<IActionResult> Details(int id, CancellationToken cancellationToken)
    {
        var result = await _documents.GetAsync(id, CurrentUser, cancellationToken);
        if (!result.Succeeded)
        {
            return FromFailure(result);
        }

        return View(new DocumentDetailsViewModel { Document = result.Value!, CanDelete = CurrentUser.IsAdmin });
    }

    [HttpGet("/documents/{id:int}/download")]
    public async Task<IActionResult> Download(int id, CancellationToken cancellationToken)
    {
        var result = await _documents.OpenFileAsync(id, CurrentUser, cancellationToken);
        if (!result.Succeeded)
        {
            return FromFailure(result);
        }

        var file = result.Value!;
        // File(..., downloadName) gera "Content-Disposition: attachment" — o navegador baixa em vez de renderizar.
        return File(file.Content, file.ContentType, file.DownloadName);
    }

    [HttpGet("/documents/upload")]
    [Authorize(Policy = Policies.CanCreateDocuments)]
    public IActionResult Upload() => View(PopulateUploadModel(new DocumentUploadViewModel()));

    [HttpPost("/documents/upload")]
    [Authorize(Policy = Policies.CanCreateDocuments)]
    [RequestSizeLimit(UploadLimits.MaxRequestBytes)]
    [RequestFormLimits(MultipartBodyLengthLimit = UploadLimits.MaxRequestBytes)]
    public async Task<IActionResult> Upload(DocumentUploadViewModel model, CancellationToken cancellationToken)
    {
        if (model.File is null && string.IsNullOrWhiteSpace(model.Content))
        {
            ModelState.AddModelError(nameof(model.Content), "Envie um arquivo ou informe o conteúdo do documento.");
        }

        if (!ModelState.IsValid)
        {
            return View(PopulateUploadModel(model));
        }

        var result = model.File is not null
            ? await _documents.UploadAsync(new UploadDocumentRequest
            {
                Title = model.Title,
                Description = model.Description,
                Classification = model.Classification,
                File = model.File
            }, CurrentUser, cancellationToken)
            : await _documents.CreateAsync(new CreateDocumentRequest
            {
                Title = model.Title,
                Description = model.Description,
                Classification = model.Classification,
                Content = model.Content!
            }, CurrentUser, cancellationToken);

        if (result.Succeeded)
        {
            FlashSuccess("Documento publicado com sucesso.");
            return RedirectToAction(nameof(Details), new { id = result.Value!.Id });
        }

        if (result.Status is ServiceStatus.Invalid or ServiceStatus.Forbidden)
        {
            AddErrors(result);
            return View(PopulateUploadModel(model));
        }

        return FromFailure(result);
    }

    [HttpPost("/documents/{id:int}/delete")]
    [Authorize(Policy = Policies.AdminOnly)]
    public async Task<IActionResult> Delete(int id, CancellationToken cancellationToken)
    {
        var result = await _documents.DeleteAsync(id, CurrentUser, cancellationToken);
        if (!result.Succeeded)
        {
            return FromFailure(result);
        }

        FlashSuccess("Documento excluído.");
        return RedirectToAction(nameof(Index));
    }

    private DocumentUploadViewModel PopulateUploadModel(DocumentUploadViewModel model)
    {
        model.ClassificationOptions = DocumentAccessPolicy.CreatableClassifications(CurrentUser)
            .Select(c => new SelectListItem(DisplayHelpers.ClassificationLabel(c), c.ToString(), c == model.Classification))
            .ToList();
        model.AllowedExtensions = _storageOptions.EffectiveAllowedExtensions;
        model.MaxFileSizeBytes = _storageOptions.MaxFileSizeBytes;
        return model;
    }
}
