using System.ComponentModel.DataAnnotations;

namespace Lab3.Exemplar.Api.Models;

public sealed class RegisterUserRequest
{
    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;

    [Required]
    public string PersonalInfo { get; set; } = string.Empty;
}

public sealed class AuthenticateUserRequest
{
    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}

public sealed class ResetPasswordRequest
{
    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string NewPassword { get; set; } = string.Empty;

    [Required]
    public string ResetToken { get; set; } = string.Empty;
}

public sealed class GetUserDataRequest
{
    [Required]
    public string UserId { get; set; } = string.Empty;

    [Required]
    public string RequestingUserId { get; set; } = string.Empty;
}
