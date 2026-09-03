@echo off
REM scripts\migrate.bat
dotnet ef %* --project .\IdentityProvider.Infrastructure\IdentityProvider.Infrastructure.csproj --startup-project .\IdentityProvider.API\IdentityProvider.Api.csproj