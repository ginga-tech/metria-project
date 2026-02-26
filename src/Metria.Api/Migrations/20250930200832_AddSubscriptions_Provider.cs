using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Metria.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddSubscriptions_Provider : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "subscriptions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    Provider = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ProviderCustomerId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    ProviderSubscriptionId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    ProviderPriceId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Plan = table.Column<string>(type: "text", nullable: false),
                    Status = table.Column<string>(type: "text", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CurrentPeriodStartUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CurrentPeriodEndUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CanceledAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_subscriptions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_subscriptions_users_UserId",
                        column: x => x.UserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_subscriptions_UserId",
                table: "subscriptions",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_subscriptions_UserId_Status_CurrentPeriodEndUtc",
                table: "subscriptions",
                columns: new[] { "UserId", "Status", "CurrentPeriodEndUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "subscriptions");
        }
    }
}
