using System.IdentityModel.Tokens.Jwt;
using System.Text;
using IdentityProvider.Api.Endpoints;
using IdentityProvider.Domain;
using IdentityProvider.Domain.Auth;
using IdentityProvider.Domain.Models;
using IdentityProvider.Infrastructure;
using IdentityProvider.Infrastructure.Database;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>()!;

builder.Services.AddInfrastructure(builder.Configuration);
builder.Services.AddDomain();
builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options => options.User.RequireUniqueEmail = true)
    .AddEntityFrameworkStores<AppDbContext>();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.MapInboundClaims = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key)),
        ClockSkew = TimeSpan.Zero,
        NameClaimType = JwtRegisteredClaimNames.Name,
        RoleClaimType = "role"
    };
});
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("bearer", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        Description = "JWT Authorization header using the Bearer scheme."
    });
    options.AddSecurityRequirement(document => new OpenApiSecurityRequirement
    {
        [new OpenApiSecuritySchemeReference("bearer", document)] = []
    });
});

builder.Services.AddSwaggerGen();

builder.Services.AddAuthorization();

builder.Services.AddOpenApi();

var app = builder.Build();

var enableSwagger = builder.Configuration.GetValue<bool>("EnableSwagger");

if (app.Environment.IsDevelopment() || enableSwagger)
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapSecuredEndpoints();

app.Run();
