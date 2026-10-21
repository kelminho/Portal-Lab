using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using SecureCorpPortal.Data;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;
using SecureCorpPortal.Tests.Infrastructure;

namespace SecureCorpPortal.Tests.Api;

public class DocumentsApiTests : IClassFixture<PortalWebApplicationFactory>
{
    private readonly PortalWebApplicationFactory _factory;

    public DocumentsApiTests(PortalWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Guest_SeesOnlyPublicDocuments()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Guest);

        var documents = await (await client.GetAsync("/api/documents")).ReadJsonAsync<List<DocumentDto>>();

        Assert.NotEmpty(documents);
        Assert.All(documents, d => Assert.Equal(DocumentClassification.Public, d.Classification));
    }

    [Fact]
    public async Task Employee_SeesPublicAndInternal_ButNotHigherClassifications()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var documents = await (await client.GetAsync("/api/documents")).ReadJsonAsync<List<DocumentDto>>();

        Assert.Contains(documents, d => d.Classification == DocumentClassification.Internal);
        Assert.DoesNotContain(documents, d => d.Classification >= DocumentClassification.Confidential);
    }

    [Fact]
    public async Task Listing_DoesNotIncludeDocumentContent()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Admin);

        var documents = await (await client.GetAsync("/api/documents")).ReadJsonAsync<List<DocumentDto>>();

        Assert.All(documents, d => Assert.Null(d.Content));
    }

    [Fact]
    public async Task Employee_CannotReadConfidentialDocument()
    {
        var confidentialId = await FirstDocumentIdAsync(DocumentClassification.Confidential);
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var response = await client.GetAsync($"/api/documents/{confidentialId}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Analyst_CanReadConfidential_ButNotRestricted()
    {
        var confidentialId = await FirstDocumentIdAsync(DocumentClassification.Confidential);
        var restrictedId = await FirstDocumentIdAsync(DocumentClassification.Restricted);
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Analyst);

        var confidential = await client.GetAsync($"/api/documents/{confidentialId}");
        var restricted = await client.GetAsync($"/api/documents/{restrictedId}");

        Assert.Equal(HttpStatusCode.OK, confidential.StatusCode);
        Assert.NotNull((await confidential.ReadJsonAsync<DocumentDto>()).Content);
        Assert.Equal(HttpStatusCode.Forbidden, restricted.StatusCode);
    }

    [Fact]
    public async Task UnknownDocument_Returns404()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Admin);

        var response = await client.GetAsync("/api/documents/999999");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Employee_CanCreateInternalDocument_AndReadItBack()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var response = await client.PostAsJsonAsync("/api/documents", new
        {
            title = "Ata de reunião",
            description = "Reunião semanal",
            classification = "Internal",
            content = "Pauta: metas do mês."
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.ReadJsonAsync<DocumentDto>();
        Assert.Equal(DocumentClassification.Internal, created.Classification);
        Assert.Equal("Juliana Lima", created.OwnerName);

        var get = await client.GetAsync($"/api/documents/{created.Id}");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
    }

    [Fact]
    public async Task Employee_CannotCreateDocumentAboveOwnClearance()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var response = await client.PostAsJsonAsync("/api/documents", new
        {
            title = "Documento sigiloso",
            classification = "Restricted",
            content = "Conteúdo"
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Guest_CannotCreateDocuments()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Guest);

        var response = await client.PostAsJsonAsync("/api/documents", new
        {
            title = "Tentativa",
            classification = "Public",
            content = "Conteúdo"
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Upload_AllowedTextFile_SucceedsAndCanBeDownloaded()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var response = await client.PostAsync("/api/documents/upload",
            BuildUpload("Relatório", "relatorio.txt", "conteúdo do relatório"u8.ToArray(), "text/plain"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.ReadJsonAsync<DocumentDto>();
        Assert.True(created.HasFile);
        Assert.Equal("relatorio.txt", created.OriginalFileName);
        Assert.Equal("text/plain", created.ContentType);

        var download = await client.GetAsync($"/api/documents/{created.Id}/download");
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal("conteúdo do relatório", Encoding.UTF8.GetString(await download.Content.ReadAsByteArrayAsync()));
        Assert.Equal("attachment", download.Content.Headers.ContentDisposition?.DispositionType);
    }

    [Fact]
    public async Task Upload_PathInFileName_IsReducedToFileNameOnly()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var response = await client.PostAsync("/api/documents/upload",
            BuildUpload("Notas", "../../etc/notas.txt", "texto"u8.ToArray(), "text/plain"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("notas.txt", (await response.ReadJsonAsync<DocumentDto>()).OriginalFileName);
    }

    [Theory]
    [InlineData("script.html")]
    [InlineData("tool.exe")]
    [InlineData("noextension")]
    public async Task Upload_DisallowedExtension_Returns400(string fileName)
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var response = await client.PostAsync("/api/documents/upload",
            BuildUpload("Arquivo", fileName, "conteúdo"u8.ToArray(), "application/octet-stream"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Upload_FileWhoseContentDoesNotMatchExtension_Returns400()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        // Extensão .pdf, mas o conteúdo não começa com a assinatura "%PDF".
        var response = await client.PostAsync("/api/documents/upload",
            BuildUpload("Falso PDF", "falso.pdf", "isto não é um pdf"u8.ToArray(), "application/pdf"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Upload_ValidPdfSignature_Succeeds()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Analyst);

        var response = await client.PostAsync("/api/documents/upload",
            BuildUpload("PDF", "manual.pdf", "%PDF-1.4 conteúdo mínimo"u8.ToArray(), "application/pdf", "Confidential"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("application/pdf", (await response.ReadJsonAsync<DocumentDto>()).ContentType);
    }

    [Fact]
    public async Task Search_FiltersByTerm()
    {
        using var client = await _factory.CreateClientAsAsync(DemoAccounts.Employee);

        var documents = await (await client.GetAsync("/api/documents?q=reembolso")).ReadJsonAsync<List<DocumentDto>>();

        var document = Assert.Single(documents);
        Assert.Contains("Reembolso", document.Title);
    }

    [Fact]
    public async Task Admin_CanDeleteDocument_EmployeeCannot()
    {
        using var employee = await _factory.CreateClientAsAsync(DemoAccounts.Employee);
        var created = await (await employee.PostAsJsonAsync("/api/documents",
            new { title = "Temporário", classification = "Public", content = "x" })).ReadJsonAsync<DocumentDto>();

        var employeeDelete = await employee.DeleteAsync($"/api/documents/{created.Id}");

        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);
        var adminDelete = await admin.DeleteAsync($"/api/documents/{created.Id}");

        Assert.Equal(HttpStatusCode.Forbidden, employeeDelete.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, adminDelete.StatusCode);
    }

    private async Task<int> FirstDocumentIdAsync(DocumentClassification classification)
    {
        using var admin = await _factory.CreateClientAsAsync(DemoAccounts.Admin);
        var documents = await (await admin.GetAsync("/api/documents")).ReadJsonAsync<List<DocumentDto>>();
        // Documentos textuais do seed (outros testes podem ter enviado arquivos sem conteúdo textual).
        return documents.First(d => d.Classification == classification && !d.HasFile).Id;
    }

    private static MultipartFormDataContent BuildUpload(
        string title, string fileName, byte[] bytes, string contentType, string classification = "Internal")
    {
        var file = new ByteArrayContent(bytes);
        file.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);

        return new MultipartFormDataContent
        {
            { new StringContent(title), "Title" },
            { new StringContent(classification), "Classification" },
            { file, "File", fileName }
        };
    }
}
