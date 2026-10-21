using SecureCorpPortal.Configuration;
using SecureCorpPortal.Models;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Tests.Unit;

public class DocumentAccessPolicyTests
{
    [Theory]
    [InlineData(AppRoles.Admin, DocumentClassification.Restricted)]
    [InlineData(AppRoles.Analyst, DocumentClassification.Confidential)]
    [InlineData(AppRoles.Employee, DocumentClassification.Internal)]
    [InlineData(AppRoles.Guest, DocumentClassification.Public)]
    public void MaxReadableClassification_FollowsRoleHierarchy(string role, DocumentClassification expected)
    {
        Assert.Equal(expected, DocumentAccessPolicy.MaxReadableClassification(role));
    }

    [Fact]
    public void UnknownRole_GetsOnlyPublic()
    {
        Assert.Equal(DocumentClassification.Public, DocumentAccessPolicy.MaxReadableClassification("SOMETHING"));
    }

    [Theory]
    [InlineData(AppRoles.Employee, DocumentClassification.Internal, true)]
    [InlineData(AppRoles.Employee, DocumentClassification.Confidential, false)]
    [InlineData(AppRoles.Analyst, DocumentClassification.Confidential, true)]
    [InlineData(AppRoles.Analyst, DocumentClassification.Restricted, false)]
    [InlineData(AppRoles.Guest, DocumentClassification.Public, true)]
    [InlineData(AppRoles.Guest, DocumentClassification.Internal, false)]
    public void CanRead_ByClassification(string role, DocumentClassification classification, bool expected)
    {
        var user = new CurrentUser(1, "u", role);
        var document = new Document { Classification = classification, OwnerId = 99 };

        Assert.Equal(expected, DocumentAccessPolicy.CanRead(user, document));
    }

    [Fact]
    public void Owner_CanAlwaysReadOwnDocument()
    {
        var user = new CurrentUser(7, "owner", AppRoles.Guest);
        var document = new Document { Classification = DocumentClassification.Restricted, OwnerId = 7 };

        Assert.True(DocumentAccessPolicy.CanRead(user, document));
    }

    [Theory]
    [InlineData(AppRoles.Guest, DocumentClassification.Public, false)]
    [InlineData(AppRoles.Employee, DocumentClassification.Internal, true)]
    [InlineData(AppRoles.Employee, DocumentClassification.Confidential, false)]
    [InlineData(AppRoles.Admin, DocumentClassification.Restricted, true)]
    public void CanCreate_LimitedByClearance(string role, DocumentClassification classification, bool expected)
    {
        Assert.Equal(expected, DocumentAccessPolicy.CanCreate(new CurrentUser(1, "u", role), classification));
    }

    [Theory]
    [InlineData(AppRoles.Admin, true)]
    [InlineData(AppRoles.Analyst, false)]
    [InlineData(AppRoles.Employee, false)]
    public void OnlyAdmin_CanDelete(string role, bool expected)
    {
        var document = new Document { OwnerId = 1 };
        Assert.Equal(expected, DocumentAccessPolicy.CanDelete(new CurrentUser(1, "u", role), document));
    }
}
