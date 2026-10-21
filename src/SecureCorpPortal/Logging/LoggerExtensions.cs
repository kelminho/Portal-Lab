namespace SecureCorpPortal.Logging;

public static class LoggerExtensions
{
    /// <summary>
    /// Abre um escopo de log com os campos de classificação do evento. Todas as
    /// mensagens escritas dentro do "using" recebem event_type/event_category.
    /// </summary>
    public static IDisposable? BeginEventScope(
        this ILogger logger,
        string eventType,
        string eventCategory,
        string? severity = null,
        string? action = null)
    {
        var state = new Dictionary<string, object?>
        {
            [LogFields.EventType] = eventType,
            [LogFields.EventCategory] = eventCategory
        };

        if (severity is not null)
        {
            state[LogFields.Severity] = severity;
        }

        if (action is not null)
        {
            state[LogFields.Action] = action;
        }

        return logger.BeginScope(state);
    }
}
