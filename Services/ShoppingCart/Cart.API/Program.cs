using Cart.API.Context;
using Cart.API.Middleware;
using Cart.Application;
using Cart.Application.Abstractions;
using Cart.Infrastructure;
using Cart.Infrastructure.Consumer;
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

    //Redis Connection
    builder.Services.Configure<RedisSettings>(options =>
    {
        options.ConnectionString =
            builder.Configuration.GetConnectionString("redis")!;
    });

    //Kafka connection
    builder.Services.Configure<KafkaSettings>(options =>
    {
        options.BootstrapServers = builder.Configuration.GetConnectionString("kafka")!;
    });

    //Add Authentication
    builder.Services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {

            options.SaveToken = true;
            options.RequireHttpsMetadata = false;       //Only for development
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

    builder.Services.AddHostedService<CartClearConsumer>();

    builder.Services.AddCors();

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    //For testing pupose only in production need to add a legit cors policy
    app.UseCors(x =>
    {
        x.AllowAnyHeader();
        x.AllowAnyMethod();
        x.AllowAnyOrigin();
    });

    //Enbale the Useforward header middleware pipeline
    app.UseForwardedHeaders();

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

