# 🛒 eCommerce Microservices

A production-style distributed eCommerce backend built with **.NET 8**, fully event-driven over **Kafka**, and orchestrated via **.NET Aspire**. Designed around microservices principles — each service owns its data, communicates asynchronously, and fails independently.

---

## Order Flow

When a user places an order, a **MassTransit Saga State Machine** coordinates the entire lifecycle across services:

```
Place Order
 └─► Lock Stock
       ├── ❌ Failed  → Notify User → Order Cancelled
       └── ✅ Locked  → Process Payment
                          ├── ❌ Failed  → Release Stock → Notify User → Order Cancelled
                          └── ✅ Success → Confirm Stock → Clear Cart → Notify User → Order Confirmed
```

Each step is a Kafka event. The saga handles all state transitions and compensation automatically. Every consumer is **idempotent** — redelivered messages are safely ignored via `CorrelationId` checks.

---

## Services

| Service | Architecture | Key Tech |
|---|---|---|
| **Order** | Clean Architecture + DDD + CQS | MassTransit Saga, MediatR, EF Core, Postgres |
| **Catalog** | Clean Architecture + DDD + CQS | MediatR, EF Core, Postgres |
| **Inventory** | Repository Pattern | EF Core, Postgres, Polly Retry, Optimistic Concurrency |
| **Cart** | Clean Architecture + CQS | MediatR, Redis |
| **Payment** | Repository Pattern | EF Core, Postgres, Configurable Failure Simulation |
| **Identity** | Repository Pattern | EF Core, ASP.NET Core Identity, Postgres |
| **Notification** | — | 🔲 Planned — SendGrid |
| **API Gateway** | — | 🔲 Planned |

---

## Key Design Decisions

- **Event-driven** — all inter-service communication via Kafka, no direct HTTP calls between services
- **Saga orchestration** — MassTransit State Machine manages order lifecycle, no distributed transaction needed
- **CQS** — Commands and Queries are separated via MediatR across Order, Catalog and Cart services
- **DDD** — Order, Catalog and Inventory model their domain with aggregates, entities, value objects and domain exceptions
- **Idempotent consumers** — every consumer checks `CorrelationId` + topic name before processing
- **Optimistic concurrency** — Inventory uses EF Core version tokens + Polly exponential backoff retry to handle concurrent stock updates
- **No magic strings** — all Kafka topic names and consumer group IDs are constants in `Shared.Messaging`
- **Options pattern** — strongly typed config with `ValidateOnStart()` across all services, no raw `IConfiguration` leaking into consumers

---

## In Pipeline

| Area | Detail |
|---|---|
| 🔲 **API Gateway** | Routing, rate limiting |
| 🔲 **Health Checks** | Per-service `/health` endpoints with Kafka, Postgres, Redis checks |
| 🔲 **OpenTelemetry** | Distributed tracing across services with `CorrelationId` propagation |
| 🔲 **Monitoring** | Prometheus + Grafana dashboards |
| 🔲 **Docker** | Dockerfiles + Docker Compose for full containerization |
| 🔲 **Notification Service** | Email notifications via SendGrid |

---

## Stack

`.NET 8` · `Kafka` · `Postgres` · `Redis` · `MassTransit` · `EF Core` · `Polly` · `MediatR` · `.NET Aspire`
