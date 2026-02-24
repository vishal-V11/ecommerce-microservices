using Identity.Api.Infrastructure;
using Identity.Api.Repository;
using Identity.Api.Settings;
using Identity.Api.Data;
using Identity.Api.Middleware;
using Identity.Api.Models;
using Identity.Api.Repository;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.HttpOverrides;

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

    builder.Services.AddControllers();
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    

    //DbContext Service Registertation
    string ConnectionString = builder.Configuration.GetConnectionString("IdentityConnection")! ;
    builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseNpgsql(ConnectionString));

    //Identity Configuration
    builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

    //Configure Jwt Settings 
    builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));

    builder.Services.AddScoped<IAuthRepository, AuthRepository>();
    builder.Services.AddScoped<IRequestContext,RequestContext>();

    // Added to get the correct Headers when this api sits behind a reverse proxy or a Gateway later in the project
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders =
            ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

        options.KnownNetworks.Clear();
        options.KnownProxies.Clear();
    });

    //Jwt Authentication Settings
    var JwtConfig = builder.Configuration.GetSection("JwtSettings");
    var jwtSettings = JwtConfig.Get<JwtSettings>();

    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;  //Do not set this to false on production
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidAudience = jwtSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey))
        };

        //Added to check between header and cookie check for the token
        //options.Events = new JwtBearerEvents
        //{
        //    OnMessageReceived = context =>
        //    {
        //        //First check Authorization header (default behavior)
        //        var authHeader = context.Request.Headers["Authorization"]
        //                            .FirstOrDefault();

        //        if (!string.IsNullOrEmpty(authHeader) &&
        //            authHeader.StartsWith("Bearer "))
        //        {
        //            context.Token = authHeader.Substring("Bearer ".Length).Trim();
        //        }
        //        else
        //        {
        //            // If no header , check cookie
        //            var cookieToken = context.Request.Cookies["accessToken"];

        //            if (!string.IsNullOrEmpty(cookieToken))
        //            {
        //                context.Token = cookieToken;
        //            }
        //        }

        //        return Task.CompletedTask;

        //    }
        //};

    });

    builder.Services.AddAuthorization();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
    builder.Services.AddHttpContextAccessor();

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
       
    }

    //Enbale the Useforward header middleware pipeline
    app.UseForwardedHeaders();

    //app.UseMiddleware<GlobalExceptionHandling>();

    app.UseHttpsRedirection();

    app.UseAuthentication();
    app.UseAuthorization();

    app.UseMiddleware<GlobalExceptionHandling>();

    app.MapControllers();

    app.Run();
}
catch(Exception ex)
{
    Log.Fatal(ex, "Identity Service terminated unexpectedly");
}
finally
{
   await Log.CloseAndFlushAsync();
}


