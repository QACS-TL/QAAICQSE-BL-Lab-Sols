using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;

namespace Lab3.Exemplar;

/// <summary>
/// Typical AI-generated user manager for Lab 3 review.
/// The vulnerabilities marked below are intentional.
/// </summary>
public sealed class UserManager
{
    private readonly SqliteConnection _connection;
    private const string DatabaseFileName = "users.db";

    // VULNERABLE: Hardcoded secret
    private readonly string _secretKey = "secret123secret123SECRET123SECRET123";

    public UserManager()
    {
        AppContext.SetSwitch("Switch.Microsoft.IdentityModel.UnsafeRelaxHmacKeySizeValidation", true);
        var databasePath = Path.Combine(AppContext.BaseDirectory, DatabaseFileName);
        _connection = new SqliteConnection($"Data Source={databasePath}");
        _connection.Open();
        EnsureSchemaAndSeedData();
    }

    public string RegisterUser(string email, string password, string personalInfo)
    {
        // VULNERABLE: No input validation, SQL injection possible
        var hashedPassword = HashPassword(password); // VULNERABLE: Weak hashing
        var query = $"INSERT INTO users (email, password, info) VALUES ('{email}', '{hashedPassword}', '{personalInfo}')";
        using var command = _connection.CreateCommand();
        command.CommandText = query;
        command.ExecuteNonQuery();
        return "User registered";
    }

    public Dictionary<string, object?>? AuthenticateUser(string email, string password)
    {
        // VULNERABLE: SQL injection, timing attack
        var hashedPassword = HashPassword(password);
        var query = $"SELECT * FROM users WHERE email = '{email}' AND password = '{hashedPassword}'";
        using var command = _connection.CreateCommand();
        command.CommandText = query;
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var row = ReadRow(reader);
        var token = CreateToken(email); // VULNERABLE: No expiration
        return new Dictionary<string, object?>
        {
            ["token"] = token,
            ["user"] = row
        };
    }

    public string ResetPassword(string email, string newPassword, string resetToken)
    {
        // VULNERABLE: No token validation
        var hashedPassword = HashPassword(newPassword);
        var query = $"UPDATE users SET password = '{hashedPassword}' WHERE email = '{email}'";
        using var command = _connection.CreateCommand();
        command.CommandText = query;
        command.ExecuteNonQuery();
        return "Password reset";
    }

    public Dictionary<string, object?>? GetUserData(string userId, string requestingUserId)
    { 
        // VULNERABLE: No authorization check
        var query = $"SELECT * FROM users WHERE id = {userId}";
        using var command = _connection.CreateCommand();
        command.CommandText = query;
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadRow(reader) : null;
    }

    private string CreateToken(string email)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            claims: new[] { new Claim("email", email) },
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // VULNERABLE: Weak hashing
    private static string HashPassword(string password)
    {
        var hash = MD5.HashData(Encoding.UTF8.GetBytes(password));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static Dictionary<string, object?> ReadRow(SqliteDataReader reader)
    {
        var row = new Dictionary<string, object?>();
        for (var index = 0; index < reader.FieldCount; index++)
        {
            row[reader.GetName(index)] = reader.IsDBNull(index) ? null : reader.GetValue(index);
        }

        return row;
    }

    private void EnsureSchemaAndSeedData()
    {
        using var createCommand = _connection.CreateCommand();
        createCommand.CommandText = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                info TEXT
            );
            """;
        createCommand.ExecuteNonQuery();

        using var countCommand = _connection.CreateCommand();
        countCommand.CommandText = "SELECT COUNT(*) FROM users";
        var userCount = Convert.ToInt64(countCommand.ExecuteScalar());
        if (userCount > 0)
        {
            return;
        }

        SeedUser("admin@example.com", "Admin!234", "System administrator");
        SeedUser("analyst@example.com", "Analyst!234", "Business analyst");
        SeedUser("tester@example.com", "Tester!234", "QA tester");
    }

    private void SeedUser(string email, string password, string personalInfo)
    {
        using var insertCommand = _connection.CreateCommand();
        insertCommand.CommandText = "INSERT INTO users (email, password, info) VALUES ($email, $password, $info)";
        insertCommand.Parameters.AddWithValue("$email", email);
        insertCommand.Parameters.AddWithValue("$password", HashPassword(password));
        insertCommand.Parameters.AddWithValue("$info", personalInfo);
        insertCommand.ExecuteNonQuery();
    }
}
