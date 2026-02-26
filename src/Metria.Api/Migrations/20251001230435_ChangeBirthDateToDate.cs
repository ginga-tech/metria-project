using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Metria.Api.Migrations
{
    /// <inheritdoc />
    public partial class ChangeBirthDateToDate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("ALTER TABLE \"users\" ALTER COLUMN \"BirthDate\" TYPE date USING (\"BirthDate\" AT TIME ZONE 'America/Sao_Paulo')::date;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("ALTER TABLE \"users\" ALTER COLUMN \"BirthDate\" TYPE date USING (\"BirthDate\" AT TIME ZONE 'America/Sao_Paulo')::date;");
        }
    }
}
