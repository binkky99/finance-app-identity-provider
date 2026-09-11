using Microsoft.AspNetCore.DataProtection;

namespace IdentityProvider.Domain.Security;

public class SigningKeyStore(IDataProtectionProvider provider)
{
    private readonly IDataProtector _protector = provider.CreateProtector("SigningKeys.PrivateKey");

    public string Protect(string pem) => _protector.Protect(pem);
    public string Unprotect(string protectedPem) => _protector.Unprotect(protectedPem);
}
