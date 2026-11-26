using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PixSmith.Authorization.DataContext.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class AddAuthenticationTickets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuthenticationTickets",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Value = table.Column<byte[]>(type: "BLOB", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    LastAccessedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthenticationTickets", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticationTickets_ExpiresAt",
                table: "AuthenticationTickets",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticationTickets_UserId",
                table: "AuthenticationTickets",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuthenticationTickets");
        }
    }
}
