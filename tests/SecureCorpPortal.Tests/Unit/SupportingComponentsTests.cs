using SecureCorpPortal.Configuration;
using SecureCorpPortal.Lab;
using SecureCorpPortal.Logging;
using SecureCorpPortal.Middleware;
using SecureCorpPortal.Models;
using SecureCorpPortal.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SecureCorpPortal.Tests.Unit;

public class SupportingComponentsTests
{
    [Theory]
    [InlineData("admin", AppRoles.Admin)]
    [InlineData(" Analyst ", AppRoles.Analyst)]
    [InlineData("EMPLOYEE", AppRoles.Employee)]
    [InlineData("root", null)]
    [InlineData(null, null)]
    public void AppRoles_Normalize(string? input, string? expected)
    {
        Assert.Equal(expected, AppRoles.Normalize(input));
    }

    [Fact]
    public void AppRoles_Highest_PicksMostPrivileged()
    {
        Assert.Equal(AppRoles.Analyst, AppRoles.Highest([AppRoles.Guest, AppRoles.Analyst]));
        Assert.Equal(AppRoles.Guest, AppRoles.Highest([]));
    }

    [Theory]
    [InlineData(AuditEventType.UserLogin, true, AuditSeverity.Info)]
    [InlineData(AuditEventType.UserLoginFailed, false, AuditSeverity.Medium)]
    [InlineData(AuditEventType.UserLockedOut, false, AuditSeverity.High)]
    [InlineData(AuditEventType.RoleChanged, true, AuditSeverity.High)]
    [InlineData(AuditEventType.DocumentUploaded, false, AuditSeverity.Medium)]
    [InlineData(AuditEventType.DocumentAccessed, true, AuditSeverity.Info)]
    public void AuditSeverityDefaults_MapsEventTypes(AuditEventType type, bool success, AuditSeverity expected)
    {
        Assert.Equal(expected, AuditSeverityDefaults.For(type, success));
    }

    [Theory]
    [InlineData("password", true)]
    [InlineData("NewPassword", true)]
    [InlineData("api_token", true)]
    [InlineData("Authorization", true)]
    [InlineData("ConnectionStrings", true)]
    [InlineData("username", false)]
    [InlineData("user_agent", false)]
    public void SensitiveData_DetectsSensitiveKeys(string key, bool expected)
    {
        Assert.Equal(expected, SensitiveData.IsSensitiveKey(key));
    }

    [Fact]
    public void LogSanitizer_RemovesControlCharactersAndTruncates()
    {
        Assert.Equal("abcdef", LogSanitizer.Clean("abc\r\ndef", 100));
        Assert.Equal("abc", LogSanitizer.Clean("abcdef", 3));
        Assert.Null(LogSanitizer.Clean("   ", 10));
        Assert.Null(LogSanitizer.Clean(null, 10));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("?q=incidentes", "q=incidentes")]
    [InlineData("?q=%27%20OR%201%3D1--", "q=%27%20OR%201%3D1--")]
    [InlineData("?q=a&token=abc123", "q=a&token=[REDACTED]")]
    [InlineData("?access%5Ftoken=abc&page=2", "access%5Ftoken=[REDACTED]&page=2")]
    [InlineData("?flag", "flag")]
    public void QueryStringLogFormatter_KeepsPayloadButMasksSensitiveParameters(string? input, string? expected)
    {
        Assert.Equal(expected, QueryStringLogFormatter.Format(input));
    }

    [Fact]
    public void QueryStringLogFormatter_TruncatesLongValues()
    {
        var result = QueryStringLogFormatter.Format("?q=" + new string('a', 5000));

        Assert.Equal(QueryStringLogFormatter.MaxLength, result!.Length);
    }

    [Theory]
    [InlineData("valid-request-id-123", true)]
    [InlineData("short", false)]
    [InlineData("has spaces in it", false)]
    [InlineData("line\nbreak-injection", false)]
    public void CorrelationMiddleware_AcceptsOnlySafeRequestIds(string incoming, bool kept)
    {
        var result = CorrelationMiddleware.ResolveRequestId(incoming);

        if (kept)
        {
            Assert.Equal(incoming, result);
        }
        else
        {
            Assert.NotEqual(incoming, result);
            Assert.Matches("^[a-f0-9]{32}$", result);
        }
    }

    [Fact]
    public void SecurityLab_IsDisabledByDefault_AndHasNoModules()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().Build();

        services.AddSecurityLab(configuration);
        var catalog = services.BuildServiceProvider().GetRequiredService<LabModuleCatalog>();

        Assert.False(catalog.Enabled);
        Assert.Empty(catalog.Available);
        Assert.Empty(catalog.Active);
    }
}
