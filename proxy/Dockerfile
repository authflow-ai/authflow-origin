FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY proxy/src/Rail.OriginProxy.csproj ./
RUN dotnet restore Rail.OriginProxy.csproj
COPY proxy/src/ ./
RUN dotnet publish Rail.OriginProxy.csproj -c Release -o /app/publish --no-self-contained --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://+:8080
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "Rail.OriginProxy.dll"]
