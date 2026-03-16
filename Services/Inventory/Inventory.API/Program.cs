using Inventory.API.Consumers;
using Inventory.API.Interfaces;
using Inventory.API.Persistence;
using Inventory.API.Services;
using Inventory.API.Settings;
using Microsoft.EntityFrameworkCore;
using Polly;
using System.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.


// EF Core
builder.Services.AddDbContext<InventoryDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("InventoryDb")));

//Services
builder.Services.AddScoped<IInventoryService, InventoryService>();

// Repository
builder.Services.AddScoped<IInventoryRepository, InventoryRepository>();
builder.Services.AddScoped<IProcessedEventsRepository, ProcessedEventsRepository>();

//kafka Settings
builder.Services.Configure<KafkaSettings>(options =>
{
    options.BootstrapServers =
        builder.Configuration.GetConnectionString("kafka")!;
});

//Polly resiliance pipeline
builder.Services.AddResiliencePipeline("inventory-stock", (pipelineBuilder,context) =>
{
    var logger = context.ServiceProvider
       .GetRequiredService<ILogger<InventoryService>>();

    pipelineBuilder
        .AddRetry(new Polly.Retry.RetryStrategyOptions
        {
            // Only retry on concurrency conflicts

            ShouldHandle = new PredicateBuilder()
                .Handle<DBConcurrencyException>(),

            // Max 3 retries (4 total attempts)
            MaxRetryAttempts = 3,

            // Start at 50ms, double each attempt
            Delay = TimeSpan.FromMilliseconds(50),
            BackoffType = DelayBackoffType.Exponential,

            // Spread retries randomly to avoid retry storms
            UseJitter = true,

            // Log every retry attempt
            OnRetry = args =>
            {
                logger.LogWarning(
                    "Concurrency conflict detected. Attempt {Attempt}/{MaxAttempts}. Waiting {Delay}ms before retry.",
                    args.AttemptNumber + 1,
                    3,
                    args.RetryDelay.TotalMilliseconds);

                return ValueTask.CompletedTask;
            }
        });


});

//Kafka Consumer
builder.Services.AddHostedService<ProductCreatedConsumer>();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
