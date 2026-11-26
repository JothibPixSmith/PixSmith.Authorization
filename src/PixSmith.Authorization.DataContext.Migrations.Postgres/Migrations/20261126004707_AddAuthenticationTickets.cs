using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PixSmith.Authorization.DataContext.Migrations.Postgres.Migrations
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
                    Id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Value = table.Column<byte[]>(type: "bytea", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastAccessedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
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
