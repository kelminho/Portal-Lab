using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers.Api;

/// <summary>
/// GET    /api/documents?q=termo     documentos visíveis ao usuário
/// GET    /api/documents/{id}        detalhes (auditado)
/// GET    /api/documents/{id}/download
/// POST   /api/documents             cria documento textual (JSON)
/// POST   /api/documents/upload      envia arquivo (multipart/form-data)
/// DELETE /api/documents/{id}        ADMIN
/// </summary>
[Authorize]
[Route("api/documents")]
public class DocumentsApiController : ApiControllerBase
{
    private readonly IDocumentService _documents;

    public DocumentsApiController(IDocumentService documents)
    {
        _documents = documents;
    }

    [HttpGet("")]
    [ProducesResponseType(typeof(IReadOnlyList<DocumentDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<DocumentDto>>> Search([FromQuery] string? q, CancellationToken cancellationToken)
    {
        var query = q?.Trim();
        if (query?.Length > 100)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "Termo de busca muito longo (máx. 100).");
        }

        return Ok(await _documents.SearchAsync(CurrentUser, query, cancellationToken));
    }

    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(DocumentDto), StatusCodes.Status200OK)]
    public async Task<ActionResult<DocumentDto>> GetById(int id, CancellationToken cancellationToken)
    {
        var result = await _documents.GetAsync(id, CurrentUser, cancellationToken);
        return result.Succeeded ? Ok(result.Value) : Failure(result);
    }

    [HttpGet("{id:int}/download")]
    public async Task<IActionResult> Download(int id, CancellationToken cancellationToken)
    {
        var result = await _documents.OpenFileAsync(id, CurrentUser, cancellationToken);
        if (!result.Succeeded)
        {
            return Failure(result);
        }

        var file = result.Value!;
        return File(file.Content, file.ContentType, file.DownloadName);
    }

    [HttpPost("")]
    [Authorize(Policy = Policies.CanCreateDocuments)]
    [ProducesResponseType(typeof(DocumentDto), StatusCodes.Status201Created)]
    public async Task<ActionResult<DocumentDto>> Create(CreateDocumentRequest request, CancellationToken cancellationToken)
    {
        var result = await _documents.CreateAsync(request, CurrentUser, cancellationToken);
        return result.Succeeded
            ? CreatedAtAction(nameof(GetById), new { id = result.Value!.Id }, result.Value)
            : Failure(result);
    }

    [HttpPost("upload")]
    [Authorize(Policy = Policies.CanCreateDocuments)]
    [Consumes("multipart/form-data")]
    [RequestSizeLimit(UploadLimits.MaxRequestBytes)]
    [RequestFormLimits(MultipartBodyLengthLimit = UploadLimits.MaxRequestBytes)]
    [ProducesResponseType(typeof(DocumentDto), StatusCodes.Status201Created)]
    public async Task<ActionResult<DocumentDto>> Upload([FromForm] UploadDocumentRequest request, CancellationToken cancellationToken)
    {
        var result = await _documents.UploadAsync(request, CurrentUser, cancellationToken);
        return result.Succeeded
            ? CreatedAtAction(nameof(GetById), new { id = result.Value!.Id }, result.Value)
            : Failure(result);
    }

    [HttpDelete("{id:int}")]
    [Authorize(Policy = Policies.AdminOnly)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Delete(int id, CancellationToken cancellationToken)
    {
        var result = await _documents.DeleteAsync(id, CurrentUser, cancellationToken);
        return result.Succeeded ? NoContent() : Failure(result);
    }
}
