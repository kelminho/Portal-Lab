namespace SecureCorpPortal.Services;

public enum ServiceStatus
{
    Success,
    NotFound,
    Forbidden,
    Invalid,
    Conflict
}

/// <summary>
/// Resultado de uma operação de negócio. Os services não conhecem HTTP;
/// os controllers traduzem o Status em 200/400/403/404 ou em páginas MVC.
/// </summary>
public class ServiceResult
{
    protected ServiceResult(ServiceStatus status, IReadOnlyList<string> errors)
    {
        Status = status;
        Errors = errors;
    }

    public ServiceStatus Status { get; }

    public IReadOnlyList<string> Errors { get; }

    public bool Succeeded => Status == ServiceStatus.Success;

    public static ServiceResult Ok() => new(ServiceStatus.Success, []);

    public static ServiceResult Fail(ServiceStatus status, params string[] errors) => new(status, errors);
}

public sealed class ServiceResult<T> : ServiceResult
{
    private ServiceResult(ServiceStatus status, T? value, IReadOnlyList<string> errors) : base(status, errors)
    {
        Value = value;
    }

    public T? Value { get; }

    public static ServiceResult<T> Ok(T value) => new(ServiceStatus.Success, value, []);

    public static new ServiceResult<T> Fail(ServiceStatus status, params string[] errors) => new(status, default, errors);
}
