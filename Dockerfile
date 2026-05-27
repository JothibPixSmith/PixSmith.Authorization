# ── Build stage ──────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy project files first so package restore is cached separately from source.
COPY OAuthSolution.sln ./
COPY src/AuthServer/AuthServer.API/PixSmith.Authorization.API.csproj                         src/AuthServer/AuthServer.API/
COPY src/AuthServer/AuthServer.Domain/PixSmith.Authorization.Domain.csproj                   src/AuthServer/AuthServer.Domain/
COPY src/AuthServer/AuthServer.Infrastructure/PixSmith.Authorization.Infrastructure.csproj   src/AuthServer/AuthServer.Infrastructure/
COPY src/AuthServer/AuthServer.Application/PixSmith.Authorization.Application.csproj         src/AuthServer/AuthServer.Application/
COPY src/BlazorClient/PixSmith.Authorization.BlazorClient.csproj                             src/BlazorClient/
COPY src/BlazorClient.Server/PixSmith.Authorization.BlazorClient.Server.csproj               src/BlazorClient.Server/
COPY PixSmith.Authorization.DataContext/PixSmith.Authorization.DataContext.csproj            PixSmith.Authorization.DataContext/
COPY PixSmith.Authorization.Repositories/PixSmith.Authorization.Repositories.csproj          PixSmith.Authorization.Repositories/
COPY PixSmith.Authorization.Services/PixSmith.Authorization.Services.csproj                  PixSmith.Authorization.Services/

RUN dotnet restore OAuthSolution.sln

# Copy the rest of the source and publish.
# Publishing the API project also builds and bundles the Blazor WASM output.
COPY . .

RUN dotnet publish src/AuthServer/AuthServer.API/PixSmith.Authorization.API.csproj \
    --configuration Release \
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
