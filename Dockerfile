# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# SecureCorp Portal — imagem para execução LOCAL em laboratório.
# Build multi-stage: o SDK compila; a imagem final contém só o runtime.
# ---------------------------------------------------------------------------

# ---------- Etapa 1: build ----------
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /source

# Restaura dependências primeiro (camada reaproveitada enquanto o .csproj não mudar)
COPY src/SecureCorpPortal/SecureCorpPortal.csproj src/SecureCorpPortal/
RUN dotnet restore src/SecureCorpPortal/SecureCorpPortal.csproj

COPY src/SecureCorpPortal/ src/SecureCorpPortal/
RUN dotnet publish src/SecureCorpPortal/SecureCorpPortal.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish \
    /p:UseAppHost=false

# ---------- Etapa 2: runtime ----------
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

ENV ASPNETCORE_HTTP_PORTS=8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_NOLOGO=true

# Diretórios graváveis: logs (montado em ./logs) e dados (uploads + chaves).
RUN mkdir -p /app/logs /app/data/uploads /app/data/keys \
    && chown -R $APP_UID /app/logs /app/data

COPY --from=build /app/publish .

# Executa como usuário sem privilégios (definido pela imagem oficial do .NET 8).
USER $APP_UID

EXPOSE 8080
ENTRYPOINT ["dotnet", "SecureCorpPortal.dll"]
