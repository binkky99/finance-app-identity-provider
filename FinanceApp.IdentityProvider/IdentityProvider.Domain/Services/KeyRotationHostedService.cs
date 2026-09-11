using System;
using System.Collections.Generic;
using System.Text;
using IdentityProvider.Domain.Security;
using IdentityProvider.Infrastructure.Database;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace IdentityProvider.Domain.Services;

public class KeyRotationHostedService(IServiceProvider services) : BackgroundService
{
    private static readonly TimeSpan RotationInterval = TimeSpan.FromDays(60);
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(12);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            using var scope = services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var provider = scope.ServiceProvider.GetRequiredService<ISigningKeyProvider>();

            var active = await db.SigningKeys.SingleOrDefaultAsync(k => k.IsActive, stoppingToken);
            if (active is null || DateTime.UtcNow - active.CreatedAt > RotationInterval)
            {
                await provider.RotateAsync();
            }

            await Task.Delay(CheckInterval, stoppingToken);
        }
    }
}
