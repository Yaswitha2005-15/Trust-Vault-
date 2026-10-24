using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TrustVault.Api.Migrations
{
    /// <inheritdoc />
    public partial class AuditCorrelationId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CorrelationId",
                table: "AuditEvents",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CorrelationId",
                table: "AuditEvents");
        }
    }
}
