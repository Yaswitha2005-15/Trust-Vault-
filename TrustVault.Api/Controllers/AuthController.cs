using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TrustVault.Api.Data;

namespace TrustVault.Api.Controllers;

public class LoginRequest
{
    [Required, EmailAddress, MaxLength(256)]
    public string Email { get; set; } = "";

    [Required, MaxLength(128)]
    public string Password { get; set; } = "";
}

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly SignInManager<AppUser> _signIn;
    private readonly UserManager<AppUser> _users;
    private readonly IAntiforgery _antiforgery;

    public AuthController(SignInManager<AppUser> signIn, UserManager<AppUser> users, IAntiforgery antiforgery)
    {
        _signIn = signIn;
        _users = users;
        _antiforgery = antiforgery;
    }

    // Issues a CSRF token. The SPA sends it back in the X-XSRF-TOKEN header.
    [HttpGet("csrf")]
    [AllowAnonymous]
    public IActionResult Csrf()
    {
        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
        Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!, new CookieOptions
        {
            HttpOnly = false, // Angular must be able to read it
            Secure = Request.IsHttps,
            SameSite = SameSiteMode.Lax,
            Path = "/"
        });
        return Ok(new { token = tokens.RequestToken });
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        // One generic answer for: unknown user, wrong password, locked out, deactivated.
        // Different answers would let an attacker discover which emails exist.
        var failure = Unauthorized(new ProblemDetails { Status = 401, Title = "Invalid email or password." });

        var user = await _users.FindByEmailAsync(request.Email);
        if (user is null || !user.IsActive) return failure;

        var result = await _signIn.PasswordSignInAsync(user, request.Password, isPersistent: false, lockoutOnFailure: true);
        if (!result.Succeeded) return failure;

        var roles = await _users.GetRolesAsync(user);
        return Ok(new { email = user.Email, roles });
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await _signIn.SignOutAsync();
        return NoContent();
    }

    [HttpGet("me")]
    [Authorize]
    public IActionResult Me() => Ok(new
    {
        email = User.FindFirstValue(ClaimTypes.Email),
        roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value)
    });
}