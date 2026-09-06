using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PixSmith.Authorization.DataContext.Migrations.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddProvisioningNonces : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ProvisioningNonces",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Nonce = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Operation = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    SignedBy = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: true),
                    UsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProvisioningNonces", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ProvisioningNonces_Nonce",
                table: "ProvisioningNonces",
                column: "Nonce",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ProvisioningNonces_UsedAt",
                table: "ProvisioningNonces",
                column: "UsedAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ProvisioningNonces");
        }
    }
}
