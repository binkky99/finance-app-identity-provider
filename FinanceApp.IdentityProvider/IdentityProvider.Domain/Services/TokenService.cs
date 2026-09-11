using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityProvider.Domain.Auth;
using IdentityProvider.Domain.Models;
using IdentityProvider.Domain.Security;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Domain.Services;

public class TokenService(IOptions<JwtSettings> jwtSettings, ISigningKeyProvider signingKeyProvider) : ITokenService
{
    private readonly JwtSettings _settings = jwtSettings.Value;

    public async Task<(string Token, DateTime ExpiresAt)> CreateAccessToken(
        ApplicationUser user, 
        IEnumerable<string> roles, 
        IEnumerable<Claim> userClaims)
    {
        var expiresAt = DateTime.UtcNow.AddMinutes(_settings.AccessTokenMinutes);
        var (kid, rsaKey) = await signingKeyProvider.GetActiveSigningKeyAsync();
        var credentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Name, $"{user.FirstName} {user.LastName}")
        };

        claims.AddRange(roles.Select(role => new Claim("role", role)));

        claims.AddRange(userClaims);

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expiresAt,
            Issuer = _settings.Issuer,
            Audience = _settings.Audience,
            SigningCredentials = credentials
        };

        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(descriptor);

        return (token, expiresAt);
    }

    public (string RawToken, string TokenHash) CreateRefreshToken()
    {
        var randomBytes = RandomNumberGenerator.GetBytes(64);
        var rawToken = Base64UrlEncoder.Encode(randomBytes);
        var tokenHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));
        return (rawToken, tokenHash);
    }
}
