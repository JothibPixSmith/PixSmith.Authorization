# See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

# This stage is used when running from VS in fast mode (Default for Debug configuration)
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081


# This stage is used to build the service project
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["src/AuthServer/AuthServer.API/PixSmith.Authorization.API.csproj", "src/AuthServer/AuthServer.API/"]
COPY ["PixSmith.Authorization.DataContext/PixSmith.Authorization.DataContext.csproj", "PixSmith.Authorization.DataContext/"]
COPY ["PixSmith.Authorization.Services/PixSmith.Authorization.Services.csproj", "PixSmith.Authorization.Services/"]
COPY ["PixSmith.Authorization.Repositories/PixSmith.Authorization.Repositories.csproj", "PixSmith.Authorization.Repositories/"]
COPY ["src/AuthServer/AuthServer.Domain/PixSmith.Authorization.Domain.csproj", "src/AuthServer/AuthServer.Domain/"]
COPY ["src/AuthServer/AuthServer.Infrastructure/PixSmith.Authorization.Infrastructure.csproj", "src/AuthServer/AuthServer.Infrastructure/"]
RUN dotnet restore "./src/AuthServer/AuthServer.API/PixSmith.Authorization.API.csproj"
COPY . .
WORKDIR "/src/src/AuthServer/AuthServer.API"
RUN dotnet build "./PixSmith.Authorization.API.csproj" -c $BUILD_CONFIGURATION -o /app/build

# This stage is used to publish the service project to be copied to the final stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./PixSmith.Authorization.API.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# This stage is used in production or when running from VS in regular mode (Default when not using the Debug configuration)
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "PixSmith.Authorization.API.dll"]