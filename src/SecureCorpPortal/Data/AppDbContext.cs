using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.Data;

/// <summary>
/// Contexto do Entity Framework Core. Herda de IdentityDbContext, que já mapeia
/// as tabelas de usuários, papéis, claims, logins e tokens.
/// Qualquer alteração aqui exige uma nova migration:
///   dotnet ef migrations add NomeDaMudanca --project src/SecureCorpPortal
/// </summary>
public class AppDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, int>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<Document> Documents => Set<Document>();

    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Nomes de tabela em snake_case (convenção comum no PostgreSQL).
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.ToTable("users");
            entity.Property(u => u.FullName).HasMaxLength(100).IsRequired();
            entity.Property(u => u.Department).HasMaxLength(100);
            entity.Property(u => u.JobTitle).HasMaxLength(100);
        });

        builder.Entity<ApplicationRole>(entity =>
        {
            entity.ToTable("roles");
            entity.Property(r => r.Description).HasMaxLength(256);
        });

        builder.Entity<IdentityUserRole<int>>().ToTable("user_roles");
        builder.Entity<IdentityUserClaim<int>>().ToTable("user_claims");
        builder.Entity<IdentityUserLogin<int>>().ToTable("user_logins");
        builder.Entity<IdentityUserToken<int>>().ToTable("user_tokens");
        builder.Entity<IdentityRoleClaim<int>>().ToTable("role_claims");

        builder.Entity<Document>(entity =>
        {
            entity.ToTable("documents");
            entity.Property(d => d.Title).HasMaxLength(200).IsRequired();
            entity.Property(d => d.Description).HasMaxLength(1000);
            entity.Property(d => d.Classification).HasConversion<string>().HasMaxLength(20);
            entity.Property(d => d.OriginalFileName).HasMaxLength(255);
            entity.Property(d => d.StoredFileName).HasMaxLength(100);
            entity.Property(d => d.ContentType).HasMaxLength(100);
            entity.Ignore(d => d.HasFile);

            entity.HasOne(d => d.Owner)
                .WithMany(u => u.Documents)
                .HasForeignKey(d => d.OwnerId)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasIndex(d => d.Classification);
            entity.HasIndex(d => d.OwnerId);
        });

        builder.Entity<AuditEvent>(entity =>
        {
            entity.ToTable("audit_events");
            entity.Property(e => e.EventType).HasConversion<string>().HasMaxLength(50);
            entity.Property(e => e.Severity).HasConversion<string>().HasMaxLength(20);
            entity.Property(e => e.Action).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Username).HasMaxLength(256);
            entity.Property(e => e.SourceIp).HasMaxLength(64);
            entity.Property(e => e.UserAgent).HasMaxLength(512);
            entity.Property(e => e.HttpMethod).HasMaxLength(10);
            entity.Property(e => e.Endpoint).HasMaxLength(512);
            entity.Property(e => e.Resource).HasMaxLength(256);
            entity.Property(e => e.Details).HasMaxLength(2000);
            entity.Property(e => e.RequestId).HasMaxLength(100);

            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.EventType);
            entity.HasIndex(e => e.UserId);
        });
    }
}
