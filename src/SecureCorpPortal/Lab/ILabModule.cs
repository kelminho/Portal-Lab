namespace SecureCorpPortal.Lab;

/// <summary>
/// Contrato para FUTUROS módulos educacionais de segurança.
///
/// Nesta etapa NENHUM módulo foi implementado: esta interface existe apenas para
/// definir onde e como eles serão conectados, mantendo-os isolados do código
/// principal. Diretrizes em docs/security/extension-points.md e Lab/README.md.
/// </summary>
public interface ILabModule
{
    /// <summary>Identificador estável, ex.: "LAB-01".</summary>
    string Id { get; }

    string Name { get; }

    /// <summary>Categoria (ex.: "authentication", "file-upload", "logging").</summary>
    string Category { get; }

    string Description { get; }

    /// <summary>Registra serviços próprios do módulo (chamado apenas se o módulo estiver habilitado).</summary>
    void ConfigureServices(IServiceCollection services);

    /// <summary>Mapeia endpoints do módulo, sempre sob o prefixo /lab/{id}.</summary>
    void MapEndpoints(IEndpointRouteBuilder endpoints);
}
