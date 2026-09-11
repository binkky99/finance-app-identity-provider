using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityProvider.Domain.Auth;
using IdentityProvider.Domain.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Domain.Services;

public interface ISigningKeyProvider
{
    Task<(string Kid, RsaSecurityKey Key)> GetActiveSigningKeyAsync();
    Task<IReadOnlyList<(string Kid, RsaSecurityKey Key)>> GetValidationKeysAsync();
    Task<SigningKey> RotateAsync();
}
