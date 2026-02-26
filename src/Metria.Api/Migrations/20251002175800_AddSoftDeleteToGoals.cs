using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Metria.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddSoftDeleteToGoals : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsActive",
                table: "goals",
                type: "boolean",
                nullable: false,
                defaultValue: true);

            migrationBuilder.AddColumn<string>(
                name: "UpdatedBy",
                table: "goals",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_goals_UserId_IsActive",
                table: "goals",
                columns: new[] { "UserId", "IsActive" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_goals_UserId_IsActive",
                table: "goals");

            migrationBuilder.DropColumn(
                name: "IsActive",
                table: "goals");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "goals");
        }
    }
}
