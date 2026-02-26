using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Metria.Api.Migrations
{
    /// <inheritdoc />
    public partial class UpdateActiveSubscriptionIndex_NoNow : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ux_subscriptions_user_active",
                table: "subscriptions");

            migrationBuilder.CreateIndex(
                name: "ux_subscriptions_user_active",
                table: "subscriptions",
                column: "UserId",
                unique: true,
                filter: "(\"Status\" IN ('Active','Trialing'))");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ux_subscriptions_user_active",
                table: "subscriptions");

            migrationBuilder.CreateIndex(
                name: "ux_subscriptions_user_active",
                table: "subscriptions",
                column: "UserId",
                unique: true,
                filter: "(\"Status\" IN ('Active','Trialing') AND \"CurrentPeriodEndUtc\" > NOW())");
        }
    }
}
