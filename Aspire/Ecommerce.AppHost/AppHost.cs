var builder = DistributedApplication.CreateBuilder(args);
var redis = builder.AddRedis("redis")
                    .WithDataVolume()                // handles persistence automatically!
                    .WithRedisCommander();           // nice UI for inspecting cart data

var mongo = builder.AddMongoDB("mongo")
                    .WithDataVolume();

var postgres = builder.AddPostgres("postgres")
                    .WithDataVolume();

var identityDb = postgres.AddDatabase("identityDb","ecommerce_identitydb");

var inventoryDb = postgres.AddDatabase("inventoryDb", "ecommerce_inventorydb");

var paymentDb = postgres.AddDatabase("paymentDb", "ecommerce_paymentsdb");
var orderDb = postgres.AddDatabase("orderDb", "ecommerce_ordersdb");

var kafka = builder.AddKafka("kafka")
                    .WithDataVolume()   
                    .WithKafkaUI();                  // UI to inspect topics/messages;

var catalog = builder.AddProject<Projects.Catalog_API>("catalog-api")
                     .WithReference(mongo)
                     .WithReference(kafka)
                     .WithReference(redis);

builder.AddProject<Projects.Identity_Api>("identity-api")
                    .WithReference(identityDb);

builder.AddProject<Projects.Inventory_API>("inventory-api")
                    .WithReference(inventoryDb)
                    .WithReference(kafka);

builder.AddProject<Projects.Cart_API>("cart-api")
                    .WithReference(redis)
                    .WithReference(kafka);

builder.AddProject<Projects.Ordering_API>("ordering-api")
                    .WithReference(orderDb)
                    .WithReference(kafka);

builder.AddProject<Projects.Payment_API>("payment-api")
                    .WithReference(paymentDb)
                    .WithReference(kafka);

builder.Build().Run();
