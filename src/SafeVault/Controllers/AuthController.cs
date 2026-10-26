using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeVault.Data;
using SafeVault.Services;

namespace SafeVault.Controllers;

public record RegisterRequest(string Username, string Email, string Password);
public record LoginRequest(string Username, string Password);

[ApiController]
[Route("api/auth")]
[EnableRateLimiting("auth")]
public class AuthController : ControllerBase
{
    private readonly UserRepository _users;
    private readonly TokenService _tokens;

    public AuthController(UserRepository users, TokenService tokens) => (_users, _tokens) = (users, tokens);

    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterRequest request)
    {
        if (!InputValidator.IsValidUsername(request.Username))
            return BadRequest(new { error = "Username must be 3-32 characters: letters, digits, '_', '.', '-'." });
        if (!InputValidator.IsValidEmail(request.Email))
            return BadRequest(new { error = "Invalid email address." });
        if (!InputValidator.IsValidPassword(request.Password))
            return BadRequest(new { error = "Password must be 10-128 characters with upper, lower and a digit." });

        // Self-registration ALWAYS creates a normal user. Admins are never created from request data.
        var user = new User(0, request.Username, request.Email, PasswordService.Hash(request.Password), Roles.User);
        return _users.Create(user)
            ? StatusCode(StatusCodes.Status201Created, new { message = "User created." })
            : Conflict(new { error = "Username is already taken." });
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // Same generic message for unknown user / wrong password / malformed input.
        var invalid = Unauthorized(new { error = "Invalid credentials." });

        if (!InputValidator.IsValidUsername(request.Username) || string.IsNullOrEmpty(request.Password)
            || request.Password.Length > 128)
            return invalid;

        var user = _users.FindByUsername(request.Username);
        if (!PasswordService.Verify(request.Password, user?.PasswordHash) || user is null)
            return invalid;

        return Ok(new { token = _tokens.CreateToken(user) });
    }
}
