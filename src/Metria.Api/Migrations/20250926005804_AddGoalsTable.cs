using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Metria.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddGoalsTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_goals_UserId_WeekId",
                table: "goals");

            migrationBuilder.DropColumn(
                name: "WeekId",
                table: "goals");

            migrationBuilder.AddColumn<string>(
                name: "Category",
                table: "goals",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "EndDate",
                table: "goals",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "Period",
                table: "goals",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "StartDate",
                table: "goals",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.CreateIndex(
                name: "IX_goals_UserId_Period_StartDate_EndDate",
                table: "goals",
                columns: new[] { "UserId", "Period", "StartDate", "EndDate" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_goals_UserId_Period_StartDate_EndDate",
                table: "goals");

            migrationBuilder.DropColumn(
                name: "Category",
                table: "goals");

            migrationBuilder.DropColumn(
                name: "EndDate",
                table: "goals");

            migrationBuilder.DropColumn(
                name: "Period",
                table: "goals");

            migrationBuilder.DropColumn(
                name: "StartDate",
                table: "goals");

            migrationBuilder.AddColumn<string>(
                name: "WeekId",
                table: "goals",
                type: "character varying(10)",
                maxLength: 10,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_goals_UserId_WeekId",
                table: "goals",
                columns: new[] { "UserId", "WeekId" });
        }
    }
}
