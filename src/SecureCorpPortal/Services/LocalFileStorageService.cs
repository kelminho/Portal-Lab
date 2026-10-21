using System.Text.RegularExpressions;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Options;
using SecureCorpPortal.Configuration;

namespace SecureCorpPortal.Services;

public sealed record FileValidationResult(bool IsValid, string? Error)
{
    public static FileValidationResult Ok() => new(true, null);

    public static FileValidationResult Fail(string error) => new(false, error);
}

public sealed record StoredFile(string StoredFileName, string OriginalFileName, string ContentType, long SizeBytes);

public interface IFileStorageService
{
    FileValidationResult Validate(IFormFile file);

    Task<StoredFile> SaveAsync(IFormFile file, CancellationToken cancellationToken = default);

    Stream? OpenRead(string storedFileName);

    void Delete(string storedFileName);
}

/// <summary>
/// Armazenamento de uploads em disco local, com as seguintes proteções:
/// - tamanho máximo configurável;
/// - lista de extensões permitidas (allowlist);
/// - verificação da assinatura binária ("magic bytes") de PDF/PNG/JPEG/Office;
/// - nome em disco gerado pelo servidor (GUID), nunca o nome enviado pelo cliente;
/// - diretório fora de wwwroot (arquivos não são servidos diretamente);
/// - Content-Type decidido pelo servidor a partir da extensão.
///
/// LAB-EXTENSION-POINT (file upload): ver docs/security/extension-points.md.
/// </summary>
public sealed partial class LocalFileStorageService : IFileStorageService
{
    private static readonly Dictionary<string, byte[][]> FileSignatures = new(StringComparer.OrdinalIgnoreCase)
    {
        [".pdf"] = [[0x25, 0x50, 0x44, 0x46]],                               // %PDF
        [".png"] = [[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]],
        [".jpg"] = [[0xFF, 0xD8, 0xFF]],
        [".jpeg"] = [[0xFF, 0xD8, 0xFF]],
        [".docx"] = [[0x50, 0x4B, 0x03, 0x04]],                              // ZIP (Office Open XML)
        [".xlsx"] = [[0x50, 0x4B, 0x03, 0x04]]
    };

    private static readonly FileExtensionContentTypeProvider ContentTypes = new();

    private readonly StorageOptions _options;
    private readonly string _root;

    public LocalFileStorageService(IOptions<StorageOptions> options, IWebHostEnvironment environment)
    {
        _options = options.Value;
        _root = Path.GetFullPath(Path.Combine(environment.ContentRootPath, _options.UploadDirectory));
    }

    public FileValidationResult Validate(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return FileValidationResult.Fail("Selecione um arquivo não vazio.");
        }

        if (file.Length > _options.MaxFileSizeBytes)
        {
            return FileValidationResult.Fail(
                $"O arquivo excede o limite de {_options.MaxFileSizeBytes / (1024 * 1024)} MB.");
        }

        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (string.IsNullOrEmpty(extension) || !_options.EffectiveAllowedExtensions.Contains(extension))
        {
            return FileValidationResult.Fail(
                $"Tipo de arquivo não permitido. Permitidos: {string.Join(", ", _options.EffectiveAllowedExtensions)}.");
        }

        if (!HasValidSignature(file, extension))
        {
            return FileValidationResult.Fail("O conteúdo do arquivo não corresponde à extensão informada.");
        }

        return FileValidationResult.Ok();
    }

    public async Task<StoredFile> SaveAsync(IFormFile file, CancellationToken cancellationToken = default)
    {
        var validation = Validate(file);
        if (!validation.IsValid)
        {
            throw new InvalidOperationException(validation.Error);
        }

        Directory.CreateDirectory(_root);

        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        var storedFileName = $"{Guid.NewGuid():N}{extension}";
        var path = ResolvePath(storedFileName);

        await using (var target = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            await file.CopyToAsync(target, cancellationToken);
        }

        return new StoredFile(storedFileName, SanitizeOriginalName(file.FileName), ContentTypeFor(extension), file.Length);
    }

    public Stream? OpenRead(string storedFileName)
    {
        var path = ResolvePath(storedFileName);
        return File.Exists(path) ? new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read) : null;
    }

    public void Delete(string storedFileName)
    {
        var path = ResolvePath(storedFileName);
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// Converte o nome armazenado em caminho absoluto, garantindo que ele
    /// permaneça dentro do diretório de uploads (proteção contra path traversal).
    /// </summary>
    private string ResolvePath(string storedFileName)
    {
        if (!StoredFileNamePattern().IsMatch(storedFileName))
        {
            throw new ArgumentException("Nome de arquivo armazenado inválido.", nameof(storedFileName));
        }

        var fullPath = Path.GetFullPath(Path.Combine(_root, storedFileName));
        if (!fullPath.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new ArgumentException("Caminho fora do diretório de uploads.", nameof(storedFileName));
        }

        return fullPath;
    }

    private static bool HasValidSignature(IFormFile file, string extension)
    {
        // Formatos de texto (.txt, .md, .csv) não possuem assinatura binária.
        if (!FileSignatures.TryGetValue(extension, out var signatures))
        {
            return true;
        }

        var maxLength = signatures.Max(s => s.Length);
        var header = new byte[maxLength];

        using var stream = file.OpenReadStream();
        var read = stream.ReadAtLeast(header, maxLength, throwOnEndOfStream: false);

        return signatures.Any(signature =>
            read >= signature.Length && header.AsSpan(0, signature.Length).SequenceEqual(signature));
    }

    private static string ContentTypeFor(string extension) =>
        ContentTypes.TryGetContentType("file" + extension, out var contentType)
            ? contentType
            : "application/octet-stream";

    /// <summary>Mantém apenas o nome do arquivo (sem diretórios) e remove caracteres inválidos.</summary>
    private static string SanitizeOriginalName(string fileName)
    {
        var name = Path.GetFileName(fileName.Replace('\\', '/'));
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(name.Where(c => !invalid.Contains(c) && !char.IsControl(c)).ToArray()).Trim();

        if (cleaned.Length == 0)
        {
            cleaned = "arquivo";
        }

        return cleaned.Length <= 255 ? cleaned : cleaned[^255..];
    }

    [GeneratedRegex("^[a-f0-9]{32}\\.[a-z0-9]{1,10}$")]
    private static partial Regex StoredFileNamePattern();
}
