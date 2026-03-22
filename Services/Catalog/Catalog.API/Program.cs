using Catalog.API.Authentication;
using Catalog.API.Context;
using Catalog.API.Middleware;
using Catalog.API.Settings;
using Catalog.Application;
using Catalog.Application.Abstractions;
using Catalog.Infrastructure;
using Catalog.Infrastructure.Persistence.Mongo.DbSeeder;
using Catalog.Infrastructure.Settings;
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


    builder.Services.AddOptions<MongoSettings>()
    .Configure(options =>
    {
        options.ConnectionString =
            builder.Configuration.GetConnectionString("mongo")!;

        options.DatabaseName =
            builder.Configuration["Mongo:DatabaseName"]!;
    })
    .ValidateOnStart();

    //Jwt Settings Configure
    builder.Services.Configure<JwtSettings>(
        builder.Configuration.GetSection("Jwt"));

    //Redis Configuration
    builder.Services.Configure<RedisSettings>(options =>
    {
        options.ConnectionString =
            builder.Configuration.GetConnectionString("redis")!;
    });

    builder.Services.Configure<KafkaSettings>(options =>
    {
        options.BootstrapServers =
            builder.Configuration.GetConnectionString("kafka")!;
    });

    //Application Dependency
    builder.Services.AddApplication();

    //Infrastructure Dependency
    builder.Services.AddInfrastructure();



    //Jwt Authentication setup 
    builder.Services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.SaveToken = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,

                ValidIssuer = builder.Configuration["Jwt:Issuer"],
                ValidAudience = builder.Configuration["Jwt:Audience"],

                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(
                        builder.Configuration["Jwt:Secret"]!))
            };
        });

    builder.Services.AddAuthorization();

    builder.Services.AddHttpContextAccessor();
    builder.Services.AddScoped<IUserContext, UserContext>();
    builder.Services.AddScoped<ICorrelationContext, CorrelationContext>();

    builder.Services.AddCors();

    var app = builder.Build();


    //Add the temporary seed data for our App
    using (var scope = app.Services.CreateScope())
    {
        var seeder = scope.ServiceProvider.GetRequiredService<DatabaseSeeder>();
        await seeder.SeedAsync();
    }

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseCors(x =>
    {
        x.AllowAnyHeader();
        x.AllowAnyMethod();
        x.AllowAnyOrigin();
    });

    //Enbale the Useforward header middleware pipeline
    app.UseForwardedHeaders();

    app.UseHttpsRedirection();

    app.UseAuthorization();

    app.UseCustomMiddleware();

    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Catalog Service terminated unexpectedly");
}
finally
{
    await Log.CloseAndFlushAsync();
}
