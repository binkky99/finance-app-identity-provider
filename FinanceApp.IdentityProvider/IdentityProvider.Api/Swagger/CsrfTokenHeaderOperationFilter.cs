using Microsoft.OpenApi;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace IdentityProvider.API.Swagger;

public class CsrfTokenHeaderOperationFilter : IOperationFilter
{
    private static readonly HashSet<string> ProtectedPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/api/auth/refresh"
    };

    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        var routePattern = context.ApiDescription.RelativePath;
        if (routePattern is null || !ProtectedPaths.Contains("/" + routePattern.TrimEnd('/')))
        {
            return;
        }

        operation.Parameters ??= [];

        operation.Parameters.Add(new OpenApiParameter
        {
            Name = "X-CSRF-Token",
            In = ParameterLocation.Header,
            Required = true,
            Description = "CSRF token issued at login, required for state-changing auth operations.",
            Schema = new OpenApiSchema { Type = JsonSchemaType.String }
        });
    }
}