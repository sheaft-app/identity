#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-buster-slim AS base
WORKDIR /app
ENV ASPNETCORE_URLS=https://*:5001;http://*:5000
ENV ASPNETCORE_HTTPS_PORT=5001
EXPOSE 5000
EXPOSE 5001

FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /src
COPY ["Sheaft.Identity/Sheaft.Identity.csproj", "Sheaft.Identity/"]
COPY ["Sheaft.Identity.Mailer/Sheaft.Identity.Mailer.csproj", "Sheaft.Identity.Mailer/"]
RUN dotnet restore "Sheaft.Identity/Sheaft.Identity.csproj"
COPY . .
WORKDIR "/src/Sheaft.Identity"
RUN dotnet build "Sheaft.Identity.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Sheaft.Identity.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Sheaft.Identity.dll"]