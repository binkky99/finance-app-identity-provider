namespace IdentityProvider.Api.Models;

public record AddRoleRequest(string Email, string Role);

public record AuthResponse(
    string Id,
    string? Email,
    IEnumerable<string> Roles,
    string AccessToken,
    DateTime AccessExpiresAt,
    string Refresh,
    DateTime RefreshExpiresAt);

public record LoginRequest(string Email, string Password);

public record RefreshRequest(string RefreshToken);

public record RegisterRequest(string FirstName, string LastName, string Email, string Password);

public record RevokeRequest(string RefreshToken);



