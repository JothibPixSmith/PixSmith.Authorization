using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PixSmith.Authorization.DataContext.Migrations.Sqlite
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
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Nonce = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Operation = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    SignedBy = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: true),
                    UsedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
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
