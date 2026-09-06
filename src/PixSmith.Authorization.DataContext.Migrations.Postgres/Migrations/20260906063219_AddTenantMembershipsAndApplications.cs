using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PixSmith.Authorization.DataContext.Migrations.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddTenantMembershipsAndApplications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TenantApplications",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TenantApplications", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TenantApplications_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TenantMemberships",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TenantMemberships", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TenantMemberships_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MembershipApplicationRoles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MembershipId = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Role = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MembershipApplicationRoles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MembershipApplicationRoles_TenantMemberships_MembershipId",
                        column: x => x.MembershipId,
                        principalTable: "TenantMemberships",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TenantMembershipRoles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MembershipId = table.Column<Guid>(type: "uuid", nullable: false),
                    Role = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TenantMembershipRoles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TenantMembershipRoles_TenantMemberships_MembershipId",
                        column: x => x.MembershipId,
                        principalTable: "TenantMemberships",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_MembershipApplicationRoles_MembershipId_ClientId_Role",
                table: "MembershipApplicationRoles",
                columns: new[] { "MembershipId", "ClientId", "Role" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TenantApplications_ClientId",
                table: "TenantApplications",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_TenantApplications_TenantId_ClientId",
                table: "TenantApplications",
                columns: new[] { "TenantId", "ClientId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TenantMembershipRoles_MembershipId_Role",
                table: "TenantMembershipRoles",
                columns: new[] { "MembershipId", "Role" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TenantMemberships_TenantId_UserId",
                table: "TenantMemberships",
                columns: new[] { "TenantId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TenantMemberships_UserId",
                table: "TenantMemberships",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MembershipApplicationRoles");

            migrationBuilder.DropTable(
                name: "TenantApplications");

            migrationBuilder.DropTable(
                name: "TenantMembershipRoles");

            migrationBuilder.DropTable(
                name: "TenantMemberships");
        }
    }
}
