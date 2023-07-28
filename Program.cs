using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var key = Encoding.ASCII.GetBytes(Settings.Secret);

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(a =>
{
    a.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    a.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(jb =>
{
    jb.RequireHttpsMetadata = false;
    jb.SaveToken = true;
    jb.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

builder.Services.AddAuthorization(a =>
{
    a.AddPolicy("ListarUsuarios", p => p.RequireClaim(ClaimTypes.Role, "admin", "employee"));
    a.AddPolicy("ApagarUsuarios", p => p.RequireClaim(ClaimTypes.Role, "admin"));
    a.AddPolicy("Employee", p => p.RequireClaim(ClaimTypes.Role, "employee"));
    a.AddPolicy("Admin", p => p.RequireClaim(ClaimTypes.Role, "admin"));
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
