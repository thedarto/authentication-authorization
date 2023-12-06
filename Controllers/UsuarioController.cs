using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NetCoreYouTube.Models;
using Newtonsoft.Json;

[ApiController]
[Route("usuario")]
public class UsuarioController: ControllerBase
{
    public IConfiguration _configuration;
    public UsuarioController(IConfiguration configuracion)
    {
        _configuration=configuracion;
    }
    [HttpPost]
    [Route("login")]
    public dynamic IniciarSesion([FromBody] Object optData)
    {
        var data=JsonConvert.DeserializeObject<dynamic>(optData.ToString());
        string user=data.usuario.ToString();
        string password=data.password.ToString();

        Usuario usuario= Usuario.DB().Where(x =>x.usuario==user&&x.password==password).FirstOrDefault();
        if(usuario==null)
        {
            return new
            {
                success=false,
                message= "Credenciales incorrectas",
                result=""
            };
        }
        var jwt = _configuration.GetSection("Jwt").Get<Jwt>();
        //las reclamaciones son informacion adicional que se incluyen en el token
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, jwt.Subject),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
            //lo que va encapsular el token
            new Claim("id", usuario.idUsuario),
            new Claim("usuario",usuario.usuario)


        };
        //encriptar la contra
        var Key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key));
        var signIn= new SigningCredentials(Key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            jwt.Issuer,
            jwt.Audience,
            claims,
            expires: DateTime.Now.AddMinutes(4),
            signingCredentials: signIn
        );
       //retorno del token 
        return new
        {
            success= true,
            message="exito",
            result= new JwtSecurityTokenHandler().WriteToken(token)
        };
    }
}