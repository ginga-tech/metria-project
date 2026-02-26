using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Metria.Api.Migrations
{
    /// <inheritdoc />
    public partial class RemoveUniqueConstraintOnActiveSubscriptions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ux_subscriptions_user_active",
                table: "subscriptions");

            migrationBuilder.CreateIndex(
                name: "IX_subscriptions_UserId",
                table: "subscriptions",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_subscriptions_UserId",
                table: "subscriptions");

            migrationBuilder.CreateIndex(
                name: "ux_subscriptions_user_active",
                table: "subscriptions",
                column: "UserId",
                unique: true,
                filter: "(\"Status\" IN ('Active','Trialing'))");
        }
    }
}
