using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityProvider.Domain.Auth;
using IdentityProvider.Domain.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Domain.Services;

public class TokenService(IOptions<JwtSettings> jwtSettings) : ITokenService
{
    private readonly JwtSettings _settings = jwtSettings.Value;

    public (string Token, DateTime ExpiresAt) CreateAccessToken(ApplicationUser user, IEnumerable<string> roles)
    {
        var expiresAt = DateTime.UtcNow.AddMinutes(_settings.AccessTokenMinutes);
        
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Key));
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Name, $"{user.FirstName} {user.LastName}")
        };

        claims.AddRange(roles.Select(role => new Claim("role", role)));

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

    public string CreateRefreshToken()
    {
        var randomBytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(randomBytes);
    }
}
