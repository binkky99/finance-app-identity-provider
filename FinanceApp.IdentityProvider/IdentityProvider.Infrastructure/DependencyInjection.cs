using IdentityProvider.Domain.Models;
using IdentityProvider.Domain.Repositories;
using IdentityProvider.Infrastructure.Database;
using IdentityProvider.Infrastructure.Repositories;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityProvider.Infrastructure;

public static class DependencyInjection
{
    public static void AddInfrastructure(this IServiceCollection services, IConfiguration configuration) 
    {
        var connectionString = configuration.GetConnectionString("IdentityDb") 
            ?? throw new InvalidOperationException("Connection string not found.");

        services.AddDbContext<AppDbContext>(
            options => options.UseSqlServer(connectionString, 
                sql => sql.MigrationsAssembly(typeof(AppDbContext).Assembly.FullName)));
        services
            .AddIdentityCore<ApplicationUser>(options => options.User.RequireUniqueEmail = true)
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<AppDbContext>();

        services.AddDataProtection()
            .PersistKeysToDbContext<AppDbContext>()
            .SetApplicationName("IdentityProvider");

        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
    }
}
