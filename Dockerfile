FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY TrustVault.Api/TrustVault.Api.csproj TrustVault.Api/
RUN dotnet restore TrustVault.Api/TrustVault.Api.csproj
COPY TrustVault.Api/ TrustVault.Api/
RUN dotnet publish TrustVault.Api/TrustVault.Api.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
# Private file store, owned by the non-root app user.
RUN mkdir -p /data/storage && chown -R $APP_UID /data
COPY --from=build /app/publish .
USER $APP_UID
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "TrustVault.Api.dll"]