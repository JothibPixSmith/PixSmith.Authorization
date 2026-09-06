# ── Build stage ──────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy project files first so package restore is cached separately from source.
#
# Restore targets the API project rather than the solution: the API's transitive
# references are exactly what the image needs, and restoring the solution would
# additionally require every test project's .csproj to be present here.
COPY src/AuthServer/AuthServer.API/PixSmith.Authorization.API.csproj                                                           src/AuthServer/AuthServer.API/
COPY src/AuthServer/AuthServer.Domain/PixSmith.Authorization.Domain.csproj                                                     src/AuthServer/AuthServer.Domain/
COPY src/AuthServer/AuthServer.Infrastructure/PixSmith.Authorization.Infrastructure.csproj                                     src/AuthServer/AuthServer.Infrastructure/
COPY src/BlazorClient/PixSmith.Authorization.BlazorClient.csproj                                                               src/BlazorClient/
COPY src/PixSmith.Authorization.DataContext/PixSmith.Authorization.DataContext.csproj                                          src/PixSmith.Authorization.DataContext/
COPY src/PixSmith.Authorization.DataContext.Migrations.Sqlite/PixSmith.Authorization.DataContext.Migrations.Sqlite.csproj      src/PixSmith.Authorization.DataContext.Migrations.Sqlite/
COPY src/PixSmith.Authorization.DataContext.Migrations.Postgres/PixSmith.Authorization.DataContext.Migrations.Postgres.csproj  src/PixSmith.Authorization.DataContext.Migrations.Postgres/
COPY src/PixSmith.Authorization.Repositories/PixSmith.Authorization.Repositories.csproj                                        src/PixSmith.Authorization.Repositories/
COPY src/PixSmith.Authorization.Services/PixSmith.Authorization.Services.csproj                                                src/PixSmith.Authorization.Services/

RUN dotnet restore src/AuthServer/AuthServer.API/PixSmith.Authorization.API.csproj

# Copy the rest of the source and publish.
# Publishing the API project also builds and bundles the Blazor WASM output.
COPY . .

# Overridden to Debug by the `debug` target below, so the debug image is produced
# from this same build stage rather than a duplicated Dockerfile.
ARG BUILD_CONFIGURATION=Release

RUN dotnet publish src/AuthServer/AuthServer.API/PixSmith.Authorization.API.csproj \
    --configuration $BUILD_CONFIGURATION \
    --no-restore \
    --output /app/publish

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# /app/data holds the SQLite database and data-protection keys.
# Mount this as a named volume so data survives container restarts.
RUN mkdir -p /app/data

COPY --from=build /app/publish .

# HTTP only — terminate TLS at the reverse proxy or load balancer.
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_HTTP_PORTS=8080

EXPOSE 8080

ENTRYPOINT ["dotnet", "PixSmith.Authorization.API.dll"]

# ── Debug stage ───────────────────────────────────────────────────────────────
#
# Built only when explicitly targeted:
#
#   docker build --target debug --build-arg BUILD_CONFIGURATION=Debug .
#
# It reuses the `build` stage above rather than duplicating it, so the debug and
# production images are always compiled from identical instructions — only the
# configuration and the base image differ.
#
# Differences from `runtime`, all of them deliberate and all of them reasons this
# image must never be deployed:
#   • SDK base image, not aspnet — larger, and ships compilers
#   • Debug configuration with portable PDBs, so breakpoints bind to source
#   • vsdbg installed, so a debugger can attach to the running process
#   • Development environment, which enables Swagger and detailed errors
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS debug
WORKDIR /app

# vsdbg is what the VS Code C# extension attaches to. Installed at build time so
# attaching does not depend on the container having network access later.
RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSL https://aka.ms/getvsdbgsh \
       | bash /dev/stdin -v latest -l /vsdbg

RUN mkdir -p /app/data

COPY --from=build /app/publish .

ENV ASPNETCORE_ENVIRONMENT=Development
ENV ASPNETCORE_HTTP_PORTS=8080

EXPOSE 8080

ENTRYPOINT ["dotnet", "PixSmith.Authorization.API.dll"]
