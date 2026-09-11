using IdentityProvider.Api.Models;
using IdentityProvider.Domain.Models;
using IdentityProvider.Domain.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using IdentityProvider.Infrastructure.Database;
using Microsoft.IdentityModel.Tokens;
using IdentityProvider.Domain.Security;

namespace IdentityProvider.Api.Endpoints;

public static class AuthEndpoints
{
    private static readonly string[] ALG_VALUES_SUPPORTED = ["RS256"];

    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/.well-known/openid-configuration", (IConfiguration config) =>
        {
            var issuer = config["JwtSettings:Issuer"];
            return Results.Json(new
            {
                issuer,
                jwks_uri = $"{issuer}/.well-known/jwks.json",
                id_token_signing_alg_values_supported = ALG_VALUES_SUPPORTED
            });
        });

        app.MapGet("/.well-known/jwks.json", async (ISigningKeyProvider provider) =>
        {
            var keys = await provider.GetValidationKeysAsync();
            var jwks = new
            {
                keys = keys.Select(k =>
                {
                    var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(k.Key);
                    jwk.Use = "sig";
                    jwk.Alg = SecurityAlgorithms.RsaSha256;
                    jwk.Kid = k.Kid;
                    return jwk;
                })
            };

            return Results.Json(jwks);
        });

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

        var userClaims = await userManager.GetClaimsAsync(user);

        var (token, expiresAt) = await tokenService.CreateAccessToken(user, roles, userClaims);

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
        var userClaims = await userManager.GetClaimsAsync(user);
        var (accessToken, accessExpiresAt) = await tokenService.CreateAccessToken(user, roles, userClaims);

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
