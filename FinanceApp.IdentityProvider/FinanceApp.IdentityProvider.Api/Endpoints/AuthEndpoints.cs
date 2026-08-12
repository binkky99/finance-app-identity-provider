using IdentityProvider.Api.Auth;
using IdentityProvider.Api.Data;
using IdentityProvider.Api.Entities;
using IdentityProvider.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IdentityProvider.Api.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth").WithTags("Auth");

        group.MapPost("/register", RegisterAsync);
        group.MapPost("/login", LoginAsync);
        group.MapPost("/refresh", RefreshAsync);
        group.MapPost("/revoke", RevokeAsync);

        group.MapPost("/add-role", AddRoleAsync)
            .RequireAuthorization(policy => policy.RequireRole(Roles.Admin));
    }

    private static async Task<IResult> AddRoleAsync(
        AddRoleRequest request,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            return Results.NotFound($"No user found with email '{request.Email}'.");
        }

        if (!await roleManager.RoleExistsAsync(request.Role))
        {
            return Results.BadRequest($"Role '{request.Role}' does not exist.");
        }

        await userManager.AddToRoleAsync(user, request.Role);
        return Results.Ok($"Role '{request.Role}' added to '{request.Email}'.");
    }

    private static async Task<IResult> RegisterAsync(RegisterRequest request, UserManager<ApplicationUser> userManager)
    {
        if (await userManager.FindByEmailAsync(request.Email) is not null)
        {
            return Results.BadRequest($"Email '{request.Email}' is already registered");
        }

        var user = new ApplicationUser
        {
            FirstName = request.FirstName,
            LastName = request.LastName,
            UserName = request.Email,
            Email = request.Email
        };

        var result = await userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return Results.BadRequest(result.Errors.Select(e => e.Description));
        }

        await userManager.AddToRoleAsync(user, Roles.User);
        return Results.Ok($"User '{request.Email}' registered successfully.");
    }

    private static async Task<IResult> LoginAsync(
        LoginRequest request,
        AppDbContext db,
        UserManager<ApplicationUser> userManager,
        ITokenService tokenService,
        IOptions<JwtSettings> jwtSettings,
        CancellationToken cancellationToken)
    {
        var user = await userManager.FindByEmailAsync(request.Email);

        // Same response for "no such user" and "wrong password" so we don't leak which emails exist.
        if (user is null || !await userManager.CheckPasswordAsync(user, request.Password))
        {
            return Results.Unauthorized();
        }

        var roles = await userManager.GetRolesAsync(user);
        var (token, expiresAt) = tokenService.CreateAccessToken(user, roles);

        var refreshToken = tokenService.CreateRefreshToken();
        var refreshExpiresAt = DateTime.UtcNow.AddDays(jwtSettings.Value.RefreshTokenDays);

        db.RefreshTokens.Add(new RefreshToken
        {
            Token = refreshToken,
            UserId = user.Id,
            Created = DateTime.UtcNow,
            Expires = expiresAt
        });

        await db.SaveChangesAsync(cancellationToken);

        return Results.Ok(new AuthResponse(user.Id, user.Email!, roles, token, expiresAt, refreshToken, refreshExpiresAt));
    }

    private static async Task<IResult> RefreshAsync(
        RefreshRequest request,
        AppDbContext db,
        UserManager<ApplicationUser> userManager,
        ITokenService tokenService,
        IOptions<JwtSettings> jwtSettings,
        CancellationToken cancellationToken)
    {
        var existing = await db.RefreshTokens
            .FirstOrDefaultAsync(t => t.Token == request.RefreshToken, cancellationToken: cancellationToken);

        if (existing is null)
        {
            return Results.Unauthorized();
        }

        if (!existing.IsActive)
        {
            if (existing.Revoked is not null)
            {
                await RevokeAllActiveTokensAsync(db, existing.UserId, cancellationToken);
            }
            return Results.Unauthorized();
        }

        var user = await userManager.FindByIdAsync(existing.UserId);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var newRefreshToken = tokenService.CreateRefreshToken();
        var refreshExpiresAt = DateTime.UtcNow.AddDays(jwtSettings.Value.RefreshTokenDays);

        existing.Revoked = DateTime.UtcNow;
        existing.ReplacedByToken = newRefreshToken;

        db.RefreshTokens.Add(new RefreshToken
        {
            Token = newRefreshToken,
            UserId = user.Id,
            Created = DateTime.UtcNow,
            Expires = refreshExpiresAt
        });
        await db.SaveChangesAsync(cancellationToken);

        var roles = await userManager.GetRolesAsync(user);
        var (accessToken, accessExpiresAt) = tokenService.CreateAccessToken(user, roles);

        return Results.Ok(new AuthResponse(
            user.Id, user.Email, roles, 
            accessToken, accessExpiresAt, 
            newRefreshToken, refreshExpiresAt));

    }

    private static async Task<IResult> RevokeAsync(RevokeRequest request, AppDbContext db)
    {
        var token = await db.RefreshTokens
            .FirstOrDefaultAsync(t => t.Token == request.RefreshToken);

        if (token is null || !token.IsActive)
        {
            return Results.NotFound("Token not found or already inactive.");
        }

        token.Revoked = DateTime.UtcNow;
        await db.SaveChangesAsync();
        return Results.Ok("Refresh token revoked.");
    }

    private static async Task RevokeAllActiveTokensAsync(AppDbContext db, string id, CancellationToken cancellationToken = default)
    {
        var tokens = db.RefreshTokens.Where(t => t.UserId == id && t.Revoked == null);

        foreach (var token in await tokens.ToListAsync(cancellationToken))
        {
            token.Revoked = DateTime.UtcNow;
        }

        await db.SaveChangesAsync(cancellationToken);
    }
}
