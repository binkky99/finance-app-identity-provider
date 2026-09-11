namespace IdentityProvider.Api.Models;

public record AddRoleRequest(string Email, string Role);

public record AuthResponse(
    string AccessToken,
    DateTime AccessExpiresAt,
    string? CsrfToken);

public record LoginRequest(string Email, string Password);

public record RegisterRequest(string FirstName, string LastName, string Email, string Password);

public record RevokeRequest(string RefreshToken);



