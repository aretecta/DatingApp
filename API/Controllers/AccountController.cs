using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using API.Data;
using API.Entities;
using API.DTOs;

using Microsoft.AspNetCore.Mvc;
using API.Interfaces;

namespace API.Controllers;

public class AccountController :  BaseApiController
{
    private readonly DataContext _context;
    private readonly ITokenService _tokenSerice;

    public AccountController(DataContext context, ITokenService tokenSerice)
    {
        _context = context;
        _tokenSerice = tokenSerice;
    }

    [HttpPost("register")] //POST: api/account/register
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        if (await UserExists(registerDto.Username)) return BadRequest("Username is taken!");
 
        using var hmac = new HMACSHA512();

        var user = new AppUser
        {
            UserName = registerDto.Username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var UserToken = new UserDto {
            Username = user.UserName,
            Token = _tokenSerice.CreateToken(user),
        };

        return UserToken;
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
    {
        var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username.ToLower());
        
        if (user == null) return Unauthorized("Invalid User!");

        using var hmac = new HMACSHA512();
       
        hmac.Key = user.PasswordSalt;

        var Hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

        if (! Hash.SequenceEqual(user.PasswordHash)) return Unauthorized("Invalid Password!");

        return new UserDto 
        {
            Username = user.UserName,
            Token = _tokenSerice.CreateToken(user),
        };
    }

    private async Task<bool> UserExists (string Username)
    {
        return await _context.Users.AnyAsync(x => x.UserName == Username.ToLower()); 
    }

}
