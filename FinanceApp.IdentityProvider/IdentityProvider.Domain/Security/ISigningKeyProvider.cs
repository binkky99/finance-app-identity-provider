using IdentityProvider.Domain.Models;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Domain.Security;

public interface ISigningKeyProvider
{
    Task<(string Kid, RsaSecurityKey Key)> GetActiveSigningKeyAsync();
    Task<IReadOnlyList<(string Kid, RsaSecurityKey Key)>> GetValidationKeysAsync();
    Task<SigningKey> RotateAsync();
}