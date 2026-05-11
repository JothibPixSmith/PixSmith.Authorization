using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PixSmith.Authorization.DataContext.Migrations
{
    /// <inheritdoc />
    public partial class ExtendOAuthClientRegistration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "AbsoluteRefreshTokenLifetimeSeconds",
                table: "OAuthClientRegistrations",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ClientSecret",
                table: "OAuthClientRegistrations",
                type: "TEXT",
                maxLength: 500,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "CorsOriginsJson",
                table: "OAuthClientRegistrations",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "LogoUri",
                table: "OAuthClientRegistrations",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "RequirePkce",
                table: "OAuthClientRegistrations",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AbsoluteRefreshTokenLifetimeSeconds",
                table: "OAuthClientRegistrations");

            migrationBuilder.DropColumn(
                name: "ClientSecret",
                table: "OAuthClientRegistrations");

            migrationBuilder.DropColumn(
                name: "CorsOriginsJson",
                table: "OAuthClientRegistrations");

            migrationBuilder.DropColumn(
                name: "LogoUri",
                table: "OAuthClientRegistrations");

            migrationBuilder.DropColumn(
                name: "RequirePkce",
                table: "OAuthClientRegistrations");
        }
    }
}
