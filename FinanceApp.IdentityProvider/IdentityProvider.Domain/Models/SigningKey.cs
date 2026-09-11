namespace IdentityProvider.Domain.Models;

public class SigningKey
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string PrivateKeyPem { get; set; } = default!;
    public string PublicKeyPem { get; set; } = default!;
    public DateTime CreatedAt { get; set; }
    public bool IsActive { get; set; }
    public DateTime? RetiredAt { get; set; }
}
