using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;

namespace SafeVault.Services;

public class TokenService
{
    private readonly string _key, _issuer, _audience;

    public TokenService(string key, string issuer, string audience)
        => (_key, _issuer, _audience) = (key, issuer, audience);

    public string CreateToken(User user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim("name", user.Username),
            new Claim("role", user.Role)
        };
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_key)), SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(_issuer, _audience, claims,
            expires: DateTime.UtcNow.AddMinutes(30), signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
