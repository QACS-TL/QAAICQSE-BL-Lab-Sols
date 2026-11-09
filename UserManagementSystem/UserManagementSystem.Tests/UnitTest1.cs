using System.Reflection;

namespace UserManagementSystem.Tests;

public class UserManagerTests
{
    [Fact]
    public void RegisterUser_ReturnsConfirmation_AndRejectsDuplicateEmail()
    {
        var manager = new UserManager();

        string result = manager.RegisterUser("alice@example.com", "Pass123!", "Alice");
        string duplicate = manager.RegisterUser("alice@example.com", "Other123!", "Other");

        Assert.StartsWith("User registration confirmed. UserId:", result);
        Assert.Equal("User registration rejected: email is already in use.", duplicate);
    }

    [Fact]
    public void AuthenticateUser_ReturnsTrueForValidCredentials_AndFalseOtherwise()
    {
        var manager = new UserManager();
        manager.RegisterUser("bob@example.com", "Secret123!", "Bob");

        bool valid = manager.AuthenticateUser("bob@example.com", "Secret123!");
        bool invalidPassword = manager.AuthenticateUser("bob@example.com", "Wrong123!");
        bool invalidEmail = manager.AuthenticateUser("missing@example.com", "Secret123!");

        Assert.True(valid);
        Assert.False(invalidPassword);
        Assert.False(invalidEmail);
    }

    [Fact]
    public void ResetPassword_UpdatesCredentials_WhenTokenIsValid()
    {
        var manager = new UserManager();
        manager.RegisterUser("carol@example.com", "Before123!", "Carol");

        string token = GetResetToken(manager, "carol@example.com");
        bool reset = manager.ResetPassword("carol@example.com", "After123!", token);

        Assert.True(reset);
        Assert.False(manager.AuthenticateUser("carol@example.com", "Before123!"));
        Assert.True(manager.AuthenticateUser("carol@example.com", "After123!"));
    }

    [Fact]
    public void ResetPassword_ReturnsFalse_WhenTokenIsInvalid()
    {
        var manager = new UserManager();
        manager.RegisterUser("dave@example.com", "Initial123!", "Dave");

        bool reset = manager.ResetPassword("dave@example.com", "New123!", "invalid-token");

        Assert.False(reset);
        Assert.True(manager.AuthenticateUser("dave@example.com", "Initial123!"));
    }

    [Fact]
    public void UpdateProfile_ReturnsConfirmation_AndPersistsData()
    {
        var manager = new UserManager();
        Guid userId = RegisterAndGetUserId(manager, "eve@example.com", "Pass123!", "Eve");

        string result = manager.UpdateProfile(userId, new Dictionary<string, string>
        {
            ["city"] = "Seattle",
            ["role"] = "Manager"
        });

        Dictionary<string, string>? data = manager.GetUserData(userId, userId);

        Assert.Equal("Profile update confirmed.", result);
        Assert.NotNull(data);
        Assert.Equal("Seattle", data!["city"]);
        Assert.Equal("Manager", data["role"]);
    }

    [Fact]
    public void DeleteUser_ReturnsConfirmation_WhenPasswordMatches_AndRemovesUser()
    {
        var manager = new UserManager();
        Guid userId = RegisterAndGetUserId(manager, "frank@example.com", "DeleteMe123!", "Frank");

        string deleteResult = manager.DeleteUser(userId, "DeleteMe123!");
        bool canAuthenticate = manager.AuthenticateUser("frank@example.com", "DeleteMe123!");

        Assert.Equal("User deletion confirmed.", deleteResult);
        Assert.False(canAuthenticate);
    }

    [Fact]
    public void DeleteUser_ReturnsRejection_WhenPasswordDoesNotMatch()
    {
        var manager = new UserManager();
        Guid userId = RegisterAndGetUserId(manager, "grace@example.com", "Correct123!", "Grace");

        string result = manager.DeleteUser(userId, "Wrong123!");

        Assert.Equal("User deletion rejected: password confirmation failed.", result);
        Assert.True(manager.AuthenticateUser("grace@example.com", "Correct123!"));
    }

    [Fact]
    public void GetUserData_ReturnsDataForSelf_AndNullForDifferentRequester()
    {
        var manager = new UserManager();
        Guid userId = RegisterAndGetUserId(manager, "henry@example.com", "View123!", "Henry");
        manager.UpdateProfile(userId, new Dictionary<string, string> { ["department"] = "IT" });

        Dictionary<string, string>? selfData = manager.GetUserData(userId, userId);
        Dictionary<string, string>? otherData = manager.GetUserData(userId, Guid.NewGuid());

        Assert.NotNull(selfData);
        Assert.Equal("henry@example.com", selfData!["email"]);
        Assert.Equal("IT", selfData["department"]);
        Assert.Null(otherData);
    }

    private static Guid RegisterAndGetUserId(UserManager manager, string email, string password, string personalInfo)
    {
        string result = manager.RegisterUser(email, password, personalInfo);
        Assert.StartsWith("User registration confirmed. UserId:", result);

        string userIdText = result.Split(':', 2)[1].Trim();
        return Guid.Parse(userIdText);
    }

    private static string GetResetToken(UserManager manager, string email)
    {
        var userIdsByEmailField = typeof(UserManager).GetField("_userIdsByEmail", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var usersByIdField = typeof(UserManager).GetField("_usersById", BindingFlags.Instance | BindingFlags.NonPublic)!;

        var userIdsByEmail = (Dictionary<string, Guid>)userIdsByEmailField.GetValue(manager)!;
        var usersById = usersByIdField.GetValue(manager)!;

        Guid userId = userIdsByEmail[email];
        object userRecord = ((System.Collections.IDictionary)usersById)[userId]!;

        PropertyInfo resetTokenProperty = userRecord.GetType().GetProperty("ResetToken", BindingFlags.Instance | BindingFlags.Public)!;
        return (string)resetTokenProperty.GetValue(userRecord)!;
    }
}
