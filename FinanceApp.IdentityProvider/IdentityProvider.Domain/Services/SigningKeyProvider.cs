using System.Security.Cryptography;
using IdentityProvider.Domain.Models;
using IdentityProvider.Domain.Security;
using IdentityProvider.Infrastructure.Database;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Domain.Services;

public class SigningKeyProvider(AppDbContext db, SigningKeyStore store) : ISigningKeyProvider
{
    private const int JwksRetentionDays = 1; // see rotation policy below

    public async Task<(string Kid, RsaSecurityKey Key)> GetActiveSigningKeyAsync()
    {
        var active = await db.SigningKeys.SingleOrDefaultAsync(k => k.IsActive)
            ?? await RotateAsync();

        var rsa = RSA.Create();
        rsa.ImportFromPem(store.Unprotect(active.PrivateKeyPem));
        return (active.Id, new RsaSecurityKey(rsa) { KeyId = active.Id });
    }

    public async Task<IReadOnlyList<(string Kid, RsaSecurityKey Key)>> GetValidationKeysAsync()
    {
        // Anything not yet expired from JWKS — active key plus any recently retired ones
        var keys = await db.SigningKeys
            .Where(k => k.IsActive || k.RetiredAt > DateTime.UtcNow.AddDays(-JwksRetentionDays))
            .ToListAsync();

        return keys.Select(k =>
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(k.PublicKeyPem);
            return (k.Id, new RsaSecurityKey(rsa) { KeyId = k.Id });
        }).ToList();
    }

    public async Task<SigningKey> RotateAsync()
    {
        using var rsa = RSA.Create(2048);

        var newKey = new SigningKey
        {
            PrivateKeyPem = store.Protect(rsa.ExportRSAPrivateKeyPem()),
            PublicKeyPem = rsa.ExportRSAPublicKeyPem(),
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        var current = await db.SigningKeys.SingleOrDefaultAsync(k => k.IsActive);
        if (current is not null)
        {
            current.IsActive = false;
            current.RetiredAt = DateTime.UtcNow;
        }

        db.SigningKeys.Add(newKey);
        await db.SaveChangesAsync();
        return newKey;
    }
}

