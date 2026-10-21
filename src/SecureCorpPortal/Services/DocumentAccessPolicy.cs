using SecureCorpPortal.Configuration;
using SecureCorpPortal.Models;
using SecureCorpPortal.Repositories;

namespace SecureCorpPortal.Services;

/// <summary>
/// Regras de acesso a documentos em UM único lugar (autorização em nível de recurso).
///
///   Papel      | Classificação máxima legível | Pode criar até
///   -----------|------------------------------|----------------
///   ADMIN      | Restricted                   | Restricted
///   ANALYST    | Confidential                 | Confidential
///   EMPLOYEE   | Internal                     | Internal
///   GUEST      | Public                       | (não cria)
///
/// Além disso, o dono sempre pode ler o próprio documento.
///
/// LAB-EXTENSION-POINT (authorization): ver docs/security/extension-points.md.
/// </summary>
public static class DocumentAccessPolicy
{
    public static DocumentClassification MaxReadableClassification(string role) => role switch
    {
        AppRoles.Admin => DocumentClassification.Restricted,
        AppRoles.Analyst => DocumentClassification.Confidential,
        AppRoles.Employee => DocumentClassification.Internal,
        _ => DocumentClassification.Public
    };

    public static IReadOnlyList<DocumentClassification> ReadableClassifications(string role)
    {
        var max = MaxReadableClassification(role);
        return Enum.GetValues<DocumentClassification>().Where(c => c <= max).ToList();
    }

    public static DocumentVisibility VisibilityFor(CurrentUser user) =>
        new(user.Id, ReadableClassifications(user.Role));

    public static bool CanRead(CurrentUser user, Document document) =>
        document.Classification <= MaxReadableClassification(user.Role) || document.OwnerId == user.Id;

    public static bool CanCreate(CurrentUser user, DocumentClassification classification) =>
        !user.IsGuest && classification <= MaxReadableClassification(user.Role);

    public static bool CanDelete(CurrentUser user, Document document) => user.IsAdmin;

    public static IReadOnlyList<DocumentClassification> CreatableClassifications(CurrentUser user) =>
        user.IsGuest ? [] : ReadableClassifications(user.Role);
}
