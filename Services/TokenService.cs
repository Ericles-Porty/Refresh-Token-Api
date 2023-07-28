using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MinimalApiAuth.Models;

public static class TokenService
{
    public static string GenerateToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler(); // tokenHandle faz a manipulação do token
        var key = Encoding.ASCII.GetBytes(Settings.Secret); // chave de criptografia
        var tokenDescriptor = new SecurityTokenDescriptor // descrição do token
        {
            Subject = new ClaimsIdentity(new Claim[]{ // identidade do token
                new Claim(ClaimTypes.Name, user.Name.ToString()), // claim é uma informação sobre o usuário
                new Claim(ClaimTypes.Role, user.Role.ToString())
            }),
            Expires = DateTime.UtcNow.AddHours(2), // tempo de expiração do token
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature) // criptografia do token
        };
        var token = tokenHandler.CreateToken(tokenDescriptor); // criação do token
        return tokenHandler.WriteToken(token); // retorna o token como string
    }

    public static string GenerateToken(IEnumerable<Claim> claims)
    {
        var tokenHandle = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(Settings.Secret);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(2),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandle.CreateToken(tokenDescriptor);
        return tokenHandle.WriteToken(token);
    }

    // public static bool ValidateToken(string token)
    // {
    //     var tokenHandle = new JwtSecurityTokenHandler();
    //     var key = Encoding.ASCII.GetBytes(Settings.Secret);
    //     var validationParameters = new TokenValidationParameters
    //     {
    //         ValidateIssuerSigningKey = true,
    //         IssuerSigningKey = new SymmetricSecurityKey(key),
    //         ValidateIssuer = false,
    //         ValidateAudience = false
    //     };
    //     try
    //     {
    //         tokenHandle.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
    //     }
    //     catch
    //     {
    //         return false;
    //     }
    //     return true;
    // }

    public static string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public static ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Settings.Secret)),
            // IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Settings.Secret)),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, TokenValidationParameters, out var securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }

    private static List<(string, string)> _refreshTokens = new();

    public static void SaveRefreshToken(string token, string refreshToken)
    {
        _refreshTokens.Add((token, refreshToken));
    }

    // public static bool ValidateRefreshToken(string token, string refreshToken)
    // {
    //     var savedRefreshToken = _refreshTokens.FirstOrDefault(x => x.Item1 == token && x.Item2 == refreshToken);
    //     if (savedRefreshToken.Item1 == null || savedRefreshToken.Item2 == null)
    //     {
    //         return false;
    //     }
    //     return true;
    // }

    public static string GetRefreshToken(string username)
    {
        return _refreshTokens.FirstOrDefault(x => x.Item1 == username).Item2;
    }

    public static void DeleteRefreshToken(string token, string refreshToken)
    {
        _refreshTokens.Remove((token, refreshToken));
    }
}