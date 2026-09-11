using System.Security.Claims;
using IdentityProvider.Domain.Models;

namespace IdentityProvider.Domain.Auth;

public interface ITokenService
{
    Task<(string Token, DateTime ExpiresAt)> CreateAccessToken(
        ApplicationUser user, 
        IEnumerable<string> roles, 
        IEnumerable<Claim> userClaims
    );
    (string RawToken, string TokenHash) CreateRefreshToken();
}
