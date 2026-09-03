using IdentityProvider.Domain.Models;

namespace IdentityProvider.Domain.Auth;

public interface ITokenService
{
    (string Token, DateTime ExpiresAt) CreateAccessToken(ApplicationUser user, IEnumerable<string> roles);
    string CreateRefreshToken();
}
