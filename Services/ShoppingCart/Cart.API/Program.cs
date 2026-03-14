using Cart.API.Context;
using Cart.API.Middleware;
using Cart.Application;
using Cart.Application.Abstractions;
using Cart.Infrastructure;
using Cart.Infrastructure.Settings;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Text;

//Setting the Logger configurations
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(new ConfigurationBuilder()
        .AddJsonFile("appsettings.json")
        .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_Environment")}.json", optional: true)
        .Build())
    .Enrich.FromLogContext()
    .CreateLogger();

try
{

    var builder = WebApplication.CreateBuilder(args);

    // Add services to the container.

    builder.Services.AddControllers();
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();


    //Add Application
    builder.Services.AddApplication();

    //Add Infrastructure
    builder.Services.AddInfraStructure();

    //Redis Configuration
    builder.Services.Configure<RedisSettings>(options =>
    {
        options.ConnectionString =
            builder.Configuration.GetConnectionString("redis")!;
    });

    //Add Authentication
    builder.Services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,

                ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
                ValidAudience = builder.Configuration["JwtSettings:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(
                        builder.Configuration["JwtSettings:SecretKey"]!
                        )
                    )
            };
        });

    builder.Services.AddAuthorization();

    builder.Services.AddHttpContextAccessor();
    builder.Services.AddScoped<IUserContext, UserContext>();
    builder.Services.AddScoped<ICorrelationContext, CorrelationContext>();

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

    app.UseCustomMiddleware();

    app.MapControllers();

    app.Run();
}
catch(Exception ex) 
{
        Log.Fatal(ex, "Catalog Service terminated unexpectedly");
}
finally
{
    await Log.CloseAndFlushAsync();
}

