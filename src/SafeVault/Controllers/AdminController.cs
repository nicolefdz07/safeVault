using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Data;
using SafeVault.Services;

namespace SafeVault.Controllers;

/// <summary>Role-based access control: only the "admin" role may call these endpoints.</summary>
[ApiController]
[Route("api/admin")]
[Authorize(Roles = Roles.Admin)]
public class AdminController : ControllerBase
{
    private readonly UserRepository _users;
    public AdminController(UserRepository users) => _users = users;

    [HttpGet("users")]
    public IActionResult ListUsers() => Ok(_users.GetAll().Select(ToDto));

    [HttpGet("users/search")]
    public IActionResult Search([FromQuery] string? q)
    {
        if (!InputValidator.IsValidSearchTerm(q))
            return BadRequest(new { error = "Invalid search term." });
        return Ok(_users.SearchByUsernamePrefix(q!).Select(ToDto));
    }

    // Never expose PasswordHash.
    private static object ToDto(User u) => new { u.Id, u.Username, u.Email, u.Role };
}
