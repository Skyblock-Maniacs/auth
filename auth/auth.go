package auth

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"

	"github.com/Skyblock-Maniacs/auth/internal/logger"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

var router *gin.Engine
var db *mongo.Client

func init() {
	logger.Info.Println("Starting Auth Service...")
	gin.SetMode(gin.ReleaseMode)
	router = gin.Default()
}

func Run(database *mongo.Client) {
	db = database
	router.Use(cors.Default())
	router.Use(gin.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	discord := router.Group("/discord")
	{
		discord.GET("/login", DiscordLoginHandler)
		discord.GET("/callback", DiscordCallbackHandler)
		discord.GET("/refresh", DiscordRefreshHandler)
		discord.GET("/logout", DiscordLogoutHandler)
	}

	router.NoRoute(func(c *gin.Context) { c.JSON(404, gin.H{"message": "Unknown endpoint"}) })

	logger.Info.Println("Auth Service routes initialized! Starting server on port: " + os.Getenv("PORT"))

	router.Run()
}

func DiscordLoginHandler(c *gin.Context) {
	redirect_uri := c.Query("redirect_uri")
	if redirect_uri == "" {
		redirect_uri = "https://sbm.gg/"
	}

	if !isValidRedirect(redirect_uri) {
		c.JSON(400, gin.H{"error": "Invalid redirect URI"})
		return
	}

	state := base64.URLEncoding.EncodeToString([]byte(redirect_uri))
	authUrl := fmt.Sprintf(
		"https://discord.com/api/oauth2/authorize?client_id=%s&response_type=code&scope=identify&state=%s&redirect_uri=%s",
		os.Getenv("DISCORD_CLIENT_ID"),
		url.QueryEscape(state),
		url.QueryEscape(os.Getenv("DISCORD_OAUTH_REDIRECT_URI")),
	)

	c.Redirect(302, authUrl)
}

func DiscordCallbackHandler(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" {
		c.JSON(400, gin.H{"error": "Missing code or state parameter"})
		return
	}

	decodedState, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid state parameter"})
		return
	}
	redirectURI := string(decodedState)
	if !isValidRedirect(redirectURI) {
		c.JSON(400, gin.H{"error": "Invalid redirect URI in state"})
		return
	}

	form := url.Values{}
	form.Set("client_id", os.Getenv("DISCORD_CLIENT_ID"))
	form.Set("client_secret", os.Getenv("DISCORD_CLIENT_SECRET"))
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", os.Getenv("DISCORD_OAUTH_REDIRECT_URI"))

	if err = setDiscordCookies(form, c); err != nil {
		c.JSON(500, gin.H{"error": "Failed to set Discord cookies: " + err.Error()})
		return
	}

	c.Redirect(302, redirectURI)
}

func DiscordRefreshHandler(c *gin.Context) {
	token := c.Query("refresh_token")
	if token == "" {
		c.JSON(400, gin.H{"error": "Missing refresh token"})
		return
	}

	form := url.Values{}
	form.Set("client_id", os.Getenv("DISCORD_CLIENT_ID"))
	form.Set("client_secret", os.Getenv("DISCORD_CLIENT_SECRET"))
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", token)

	if err := setDiscordCookies(form, c); err != nil {
		c.JSON(500, gin.H{"error": "Failed to refresh Discord token: " + err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "Token refreshed successfully"})
}

func DiscordLogoutHandler(c *gin.Context) {
	redirect_uri := c.Query("redirect_uri")
	if redirect_uri == "" {
		redirect_uri = "https://sbm.gg/"
	}

	if !isValidRedirect(redirect_uri) {
		c.JSON(400, gin.H{"error": "Invalid redirect URI"})
		return
	}

	setEnvCookie(c, "discord_access_token", "", -1)
	setEnvCookie(c, "discord_refresh_token", "", -1)
	setEnvCookie(c, "sbm_jwt", "", -1)

	c.Redirect(302, redirect_uri)
}
