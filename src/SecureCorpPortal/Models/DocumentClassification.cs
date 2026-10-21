namespace SecureCorpPortal.Models;

/// <summary>
/// Classificação da informação, do menos para o mais sensível.
/// A ordem numérica é usada para comparar com o nível máximo de cada papel
/// (ver Services/DocumentAccessPolicy.cs). No banco é gravado como texto.
/// </summary>
public enum DocumentClassification
{
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3
}
