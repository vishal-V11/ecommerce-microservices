using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Payment.API.Abstraction;
using Payment.API.Consumers;
using Payment.API.Data;
using Payment.API.Repositories;
using Payment.API.Settings;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

//builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services
    .AddOptions<KafkaSettings>()
    .BindConfiguration("kafka")
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddOptions<PaymentSettings>()
    .BindConfiguration(PaymentSettings.SectionName)
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddOptions<DatabaseSettings>()
    .BindConfiguration(DatabaseSettings.SectionName)
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddDbContext<PaymentDbContext>((sp,options) =>
{
    var dbOptions = sp.GetRequiredService<IOptions<DatabaseSettings>>().Value;
    options.UseNpgsql(dbOptions.ConnectionString)
           .UseSnakeCaseNamingConvention();
});

builder.Services.AddScoped<IPaymentRepository, PaymentRepository>();

//Register the background service
builder.Services.AddHostedService<PaymentProcessRequestedConsumer>();

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

app.UseHttpsRedirection();

app.UseAuthorization();

//app.MapControllers();

app.Run();
