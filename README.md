# 🛡️ Skyblock Maniacs Auth Service
Skyblock Maniacs Auth service is a custom authentication service for the Skyblock Maniacs Discord server and its related web services.
It is built using Go, utilizing the [Gin](https://github.com/gin-gonic/gin) web framework for handling HTTP requests and responses.

### Live Instance
You can access the live instance of the Skyblock Maniacs Auth service at [auth.sbm.gg](https://auth.sbm.gg/).

## 🚀 Features
- [Discord OAuth2](https://discord.com/developers/docs/topics/oauth2#oauth2) authentication
- [MC-Auth OAuth2](https://github.com/Mc-Auth-com/Mc-Auth) authentication
- JWT token generation and validation

## ⚒️ Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Skyblock-Maniacs/auth.git
   ```
2. Navigate to the project directory:
   ```bash
    cd auth
    ```
3. Install dependencies:
    ```bash
    go mod tidy
    ```
4. Set up environment variables:
    Create a `.env` file in the root directory with the following variables:
    ```env
    PORT=3000
    JWT_SECRET=your_jwt_secret_key

    DISCORD_CLIENT_ID=your_discord_client_id
    DISCORD_CLIENT_SECRET=your_discord_client_secret
    DISCORD_REDIRECT_URI=http://localhost:8080/callback

    MCAUTH_CLIENT_ID=your_mc_auth_client_id
    MCAUTH_CLIENT_SECRET=your_mc_auth_client_secret
    MCAUTH_OAUTH_REDIRECT_URI=http://localhost:3000/minecraft/callback

    MONGO_URI=mongodb://localhost:27017/your_database_name
    ```
    Optionally, you can use the [.env.example](./.env.example) file as a template with `cp .env.example .env`.
5. Run the application:
    ```bash
    go run ./cmd/auth
    ```
6. Access the service:
    Check the webservice is running at `http://localhost:3000/healthz`.

## ⚠️ Deployment
This app is designed to be run in a Docker container. To deploy, use the provided [Dockerfile](./Dockerfile).
The live version of the app is hosted on [Skyblock Maniacs Auth](https://auth.sbm.gg/) using [Dokploy](https://dokploy.com/).
