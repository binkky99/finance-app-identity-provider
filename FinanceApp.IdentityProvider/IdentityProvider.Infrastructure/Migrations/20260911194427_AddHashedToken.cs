using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IdentityProvider.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddHashedToken : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ReplacedByToken",
                table: "RefreshTokens");

            migrationBuilder.RenameColumn(
                name: "Token",
                table: "RefreshTokens",
                newName: "HashedToken");

            migrationBuilder.AddColumn<int>(
                name: "ParentTokenId",
                table: "RefreshTokens",
                type: "int",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ParentTokenId",
                table: "RefreshTokens");

            migrationBuilder.RenameColumn(
                name: "HashedToken",
                table: "RefreshTokens",
                newName: "Token");

            migrationBuilder.AddColumn<string>(
                name: "ReplacedByToken",
                table: "RefreshTokens",
                type: "nvarchar(max)",
                nullable: true);
        }
    }
}
