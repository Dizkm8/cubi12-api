﻿# Stage 1: Build environment with SDK
FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build-env
WORKDIR /App

# Copy the entire content of the current directory to the container
COPY . ./

# Restore dependencies as distinct layers
RUN dotnet restore && dotnet publish -c Release -o out

# Stage 2: Runtime environment with only runtime dependencies
FROM mcr.microsoft.com/dotnet/aspnet:7.0
WORKDIR /App

# Copy the published output from the build environment
COPY --from=build-env /App/out .

# Set environment variables for the ASP.NET Core app
ENV ASPNETCORE_URLS=http://+:80

# Expose port 80 for the application
EXPOSE 80

# Specify the entry point for the application
ENTRYPOINT ["dotnet", "Cubitwelve.dll"]
