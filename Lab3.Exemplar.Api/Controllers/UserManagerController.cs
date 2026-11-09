using Lab3.Exemplar;
using Lab3.Exemplar.Api.Models;
using Microsoft.AspNetCore.Mvc;

namespace Lab3.Exemplar.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class UserManagerController : ControllerBase
{
    private readonly UserManager _userManager;

    public UserManagerController(UserManager userManager)
    {
        _userManager = userManager;
    }

    [HttpPost("register")]
    public ActionResult<string> Register([FromBody] RegisterUserRequest request)
    {
        var result = _userManager.RegisterUser(request.Email, request.Password, request.PersonalInfo);
        return Ok(result);
    }

    [HttpPost("authenticate")]
    public ActionResult<Dictionary<string, object?>> Authenticate([FromBody] AuthenticateUserRequest request)
    {
        var result = _userManager.AuthenticateUser(request.Email, request.Password);
        return result is null ? Unauthorized() : Ok(result);
    }

    [HttpPost("reset-password")]
    public ActionResult<string> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var result = _userManager.ResetPassword(request.Email, request.NewPassword, request.ResetToken);
        return Ok(result);
    }

    [HttpPost("user-data")]
    public ActionResult<Dictionary<string, object?>> GetUserData([FromBody] GetUserDataRequest request)
    {
        var result = _userManager.GetUserData(request.UserId, request.RequestingUserId);
        return result is null ? NotFound() : Ok(result);
    }
}
