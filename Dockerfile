FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY . .
RUN dotnet restore src/Metria.Api/Metria.Api.csproj
RUN dotnet publish src/Metria.Api/Metria.Api.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app

COPY --from=build /app/publish .
CMD ["sh", "-c", "dotnet Metria.Api.dll --urls http://0.0.0.0:${PORT:-8080}"]
