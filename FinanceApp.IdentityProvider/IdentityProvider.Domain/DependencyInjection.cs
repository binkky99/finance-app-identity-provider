using IdentityProvider.Domain.Auth;
using IdentityProvider.Domain.Services;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityProvider.Domain;

public static class DependencyInjection
{
    public static IServiceCollection AddDomain(this IServiceCollection services)
    {
        services.AddScoped<ITokenService, TokenService>();

        return services;
    }
}
