using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Metria.Api.Auth;

public static class ClaimsPrincipalExtensions
{
    public static string? GetEmail(this ClaimsPrincipal principal)
    {
        return principal.FindFirstValue(ClaimTypes.Email)
            ?? principal.FindFirstValue(JwtRegisteredClaimNames.Email);
    }
}
