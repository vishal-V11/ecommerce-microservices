var builder = DistributedApplication.CreateBuilder(args);
var redis = builder.AddRedis("redis")
                    .WithDataVolume()                // handles persistence automatically!
                    .WithRedisCommander();           // nice UI for inspecting cart data

var mongo = builder.AddMongoDB("mongo")
                    .WithDataVolume();


var kafka = builder.AddKafka("kafka")
                    .WithKafkaUI();                  // UI to inspect topics/messages;

var catalog = builder.AddProject<Projects.Catalog_API>("catalog-api")
                     .WithReference(mongo)
                     .WithReference(kafka)
                     .WithReference(redis);

builder.AddProject<Projects.Cart_API>("cart-api");

builder.Build().Run();
