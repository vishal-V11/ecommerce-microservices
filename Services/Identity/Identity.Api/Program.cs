using Identity.Api.Data;
using Identity.Api.Infrastructure;
using Identity.Api.Interface;
using Identity.Api.Middleware;
using Identity.Api.Models;
using Identity.Api.Persistence.Repository;
using Identity.Api.Settings;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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

    builder.Services.AddControllers();
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    

    //DbContext Service Registertation
    builder.Services.AddDbContext<ApplicationDbContext>(options => 
        options.UseNpgsql(
            builder.Configuration.GetConnectionString("identityDb"),
            npgsqlOptions =>
            {
                npgsqlOptions.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(10),
                errorCodesToAdd: null);
            })
            .UseSnakeCaseNamingConvention()
        );

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
            ValidIssuer = jwtSettings!.Issuer,
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

    builder.Services.AddCors();

    builder.Services.AddAuthorization();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
    builder.Services.AddHttpContextAccessor();

    var app = builder.Build();


    // Auto-migrate on startup
    using (var scope = app.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.Database.MigrateAsync();
    }

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
       
    }

    //For testing purpose only
    app.UseCors(x =>
    {
        
        x.AllowAnyMethod();
        x.AllowAnyOrigin();
        x.AllowAnyHeader();
    });

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


