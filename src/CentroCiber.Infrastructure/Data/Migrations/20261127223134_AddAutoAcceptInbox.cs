using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CentroCiber.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAutoAcceptInbox : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AutoAcceptInbox",
                table: "Settings",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.UpdateData(
                table: "Settings",
                keyColumn: "Id",
                keyValue: 1,
                column: "AutoAcceptInbox",
                value: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AutoAcceptInbox",
                table: "Settings");
        }
    }
}
