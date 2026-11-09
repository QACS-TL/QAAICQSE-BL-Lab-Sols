using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Lab3.Exemplar.Tests;

[Collection("UserManager tests")]
public sealed class UserManagerTests : IDisposable
{
    private readonly UserManager _manager;

    public UserManagerTests()
    {
        _manager = new UserManager();
        EnsureSchemaAndResetData(_manager);
    }

    [Fact]
    public void RegisterUser_WhenValidDataProvided_ReturnsSuccessAndPersistsUser()
    {
        var result = _manager.RegisterUser("alice@example.com", "P@ssw0rd!", "Alice");
        var row = GetUserByEmail("alice@example.com");

        Assert.Equal("User registered", result);
        Assert.NotNull(row);
        Assert.Equal("alice@example.com", row["email"]?.ToString());
        Assert.Equal("Alice", row["info"]?.ToString());
    }

    [Fact]
    public void AuthenticateUser_WhenPasswordIsIncorrect_ReturnsNull()
    {
        _manager.RegisterUser("alice@example.com", "P@ssw0rd!", "Alice");

        var authResult = _manager.AuthenticateUser("alice@example.com", "wrong-password");

        Assert.Null(authResult);
    }

    [Fact]
    public void ResetPassword_WhenCalled_UpdatesPasswordForSubsequentAuthentication()
    {
        _manager.RegisterUser("alice@example.com", "old-password", "Alice");

        var result = _manager.ResetPassword("alice@example.com", "new-password", "ignored-token");
        var row = GetUserByEmail("alice@example.com");
        var expectedHash = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes("new-password"))).ToLowerInvariant();

        Assert.Equal("Password reset", result);
        Assert.NotNull(row);
        Assert.Equal(expectedHash, row["password"]?.ToString());
    }

    [Fact]
    public void GetUserData_WhenUserExists_ReturnsUserRow()
    {
        _manager.RegisterUser("alice@example.com", "P@ssw0rd!", "Alice");
        var user = GetUserByEmail("alice@example.com");

        var userId = user!["id"]?.ToString();
        var retrieved = _manager.GetUserData(userId!, "any-requester");

        Assert.NotNull(retrieved);
        Assert.Equal("alice@example.com", retrieved["email"]?.ToString());
        Assert.Equal("Alice", retrieved["info"]?.ToString());
    }

    [Fact]
    public void GetUserData_WhenUserDoesNotExist_ReturnsNull()
    {
        var retrieved = _manager.GetUserData("999", "any-requester");

        Assert.Null(retrieved);
    }

    public void Dispose()
    {
        DisposeManagerConnection(_manager);
    }

    private static void EnsureSchemaAndResetData(UserManager manager)
    {
        var connection = GetManagerConnection(manager);
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                info TEXT
            );
            DELETE FROM users;
            """;
        command.ExecuteNonQuery();
    }

    private static void DisposeManagerConnection(UserManager manager)
    {
        GetManagerConnection(manager).Dispose();
    }

    private static SqliteConnection GetManagerConnection(UserManager manager)
    {
        var field = typeof(UserManager).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic);
        return Assert.IsType<SqliteConnection>(field?.GetValue(manager));
    }

    private Dictionary<string, object?>? GetUserByEmail(string email)
    {
        var connection = GetManagerConnection(_manager);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM users WHERE email = $email";
        command.Parameters.AddWithValue("$email", email);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var row = new Dictionary<string, object?>();
        for (var index = 0; index < reader.FieldCount; index++)
        {
            row[reader.GetName(index)] = reader.IsDBNull(index) ? null : reader.GetValue(index);
        }

        return row;
    }
}

[CollectionDefinition("UserManager tests", DisableParallelization = true)]
public sealed class UserManagerTestsCollection;
