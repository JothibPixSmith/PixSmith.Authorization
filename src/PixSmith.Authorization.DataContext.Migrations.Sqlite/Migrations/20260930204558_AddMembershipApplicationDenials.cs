using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PixSmith.Authorization.DataContext.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class AddMembershipApplicationDenials : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "MembershipApplicationDenials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    MembershipId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MembershipApplicationDenials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MembershipApplicationDenials_TenantMemberships_MembershipId",
                        column: x => x.MembershipId,
                        principalTable: "TenantMemberships",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_MembershipApplicationDenials_MembershipId_ClientId",
                table: "MembershipApplicationDenials",
                columns: new[] { "MembershipId", "ClientId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MembershipApplicationDenials");
        }
    }
}
