using Microsoft.AspNetCore.Mvc;
using MinimalApiAuth.Models;
using MinimalApiAuth.Repositories;

namespace RefreshTokenAuth.Controllers;

[ApiController]
public class LoginController : ControllerBase
{
    [HttpPost("login")]
    public IActionResult Login([FromBody] User model)
    {
        var user = UserRepository.Get(model.Name, model.Password);
        if (user == null)
            return NotFound(new { message = "Usuário ou senha inválidos" });

        var token = TokenService.GenerateToken(user);

        var refreshToken = TokenService.GenerateRefreshToken();
        TokenService.SaveRefreshToken(user.Name, refreshToken);

        user.Password = string.Empty;

        return Ok(new
        {
            user = user,
            token = token,
            refreshToken = refreshToken
        });
    }

    [HttpPost("refresh")]
    public IActionResult Refresh(string token, string refreshToken)
    {
        var principal = TokenService.GetPrincipalFromExpiredToken(token);
        var username = principal.Identity!.Name ?? "";
        var savedRefreshToken = TokenService.GetRefreshToken(username);
        if (savedRefreshToken != refreshToken)
            return BadRequest(new { message = "Invalid refresh token" });

        var newToken = TokenService.GenerateToken(principal.Claims);
        var newRefreshToken = TokenService.GenerateRefreshToken();

        TokenService.DeleteRefreshToken(token, refreshToken);
        TokenService.SaveRefreshToken(username, newRefreshToken);

        return Ok(new
        {
            token = newToken,
            refreshToken = newRefreshToken
        });
    }
}