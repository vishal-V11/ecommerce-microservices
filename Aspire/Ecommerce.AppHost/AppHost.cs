var builder = DistributedApplication.CreateBuilder(args);
var redis = builder.AddRedis("redis");

var mongo = builder.AddMongoDB("mongo")
                    .WithDataVolume();


var kafka = builder.AddKafka("kafka");

var catalog = builder.AddProject<Projects.Catalog_API>("catalog")
                     .WithReference(mongo)
                     .WithReference(kafka)
                     .WithReference(redis);

builder.Build().Run();
