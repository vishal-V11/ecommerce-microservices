using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Payment.API.Abstraction;
using Payment.API.Consumers;
using Payment.API.Data;
using Payment.API.Messaging;
using Payment.API.Repositories;
using Payment.API.Settings;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

//builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.Configure<KafkaSettings>(options =>
{
    options.BootstrapServers = 
        builder.Configuration.GetConnectionString("kafka")!;
});

builder.Services
    .AddOptions<PaymentSettings>()
    .BindConfiguration(PaymentSettings.SectionName)
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.Configure<DatabaseSettings>(options =>
{
    options.ConnectionString =
        builder.Configuration.GetConnectionString("paymentDb")!;
});


//Database configuration
builder.Services.AddDbContext<PaymentDbContext>((sp,options) =>
{
    var dbOptions = sp.GetRequiredService<IOptions<DatabaseSettings>>().Value;
    options.UseNpgsql(dbOptions.ConnectionString,

          npgsqlOptions =>
          {
              npgsqlOptions.EnableRetryOnFailure(
              maxRetryCount: 5,
              maxRetryDelay: TimeSpan.FromSeconds(10),
              errorCodesToAdd: null);
          }
    )
    .UseSnakeCaseNamingConvention();
});

builder.Services.AddScoped<IPaymentRepository, PaymentRepository>();
builder.Services.AddSingleton<KafkaFactory>();

//Register the background service
builder.Services.AddHostedService<PaymentProcessRequestedConsumer>();

builder.Services.AddCors();

var app = builder.Build();

// Auto-migrate on startup
using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<PaymentDbContext>();
    await db.Database.MigrateAsync();
}

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

//app.UseAuthorization();

//app.MapControllers();

app.Run();
