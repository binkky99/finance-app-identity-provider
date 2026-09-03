namespace IdentityProvider.Domain.Models;

public class RefreshToken
{
    public int Id { get; set; }
    public string Token { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public DateTime Created { get; set; }
    public DateTime Expires { get; set; }
    public DateTime? Revoked { get; set; }

    public string? ReplacedByToken { get; set; }

    public bool IsActive => Revoked is null && DateTime.UtcNow < Expires;
}
