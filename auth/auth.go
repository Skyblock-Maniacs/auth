package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Skyblock-Maniacs/auth/internal/logger"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

	minecraft := router.Group("/minecraft")
	{
		minecraft.GET("/login", MinecraftLoginHandler)
		minecraft.GET("/callback", MinecraftCallbackHandler)
		minecraft.GET("/logout", MinecraftLogoutHandler)
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

func MinecraftLoginHandler(c *gin.Context) {
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
		"https://mc-auth.com/oAuth2/authorize?client_id=%s&response_type=code&scope=profile&state=%s&redirect_uri=%s",
		os.Getenv("MCAUTH_CLIENT_ID"),
		url.QueryEscape(state),
		url.QueryEscape(os.Getenv("MCAUTH_OAUTH_REDIRECT_URI")),
	)

	c.Redirect(302, authUrl)
}

func MinecraftCallbackHandler(c *gin.Context) {
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

	payload := map[string]string{
		"client_id":     os.Getenv("MCAUTH_CLIENT_ID"),
		"client_secret": os.Getenv("MCAUTH_CLIENT_SECRET"),
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  os.Getenv("MCAUTH_OAUTH_REDIRECT_URI"),
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create request payload: " + err.Error()})
		return
	}

	req, err := http.NewRequest(http.MethodPost, "https://mc-auth.com/oAuth2/token", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create request: " + err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to get token: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.JSON(500, gin.H{"error": "Failed to get token: " + resp.Status})
		return
	}
	var tokenResponse struct {
		AccessToken string                 `json:"access_token"`
		ExpiresIn   int                    `json:"expires_in"`
		Scope       string                 `json:"scope"`
		Data        map[string]interface{} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode token response: " + err.Error()})
		return
	}
	if tokenResponse.Data == nil {
		c.JSON(500, gin.H{"error": "Invalid token response: missing data"})
		return
	}

	claims := jwt.MapClaims{
		"username": tokenResponse.Data["profile"].(map[string]interface{})["name"].(string),
		"uuid":     tokenResponse.Data["profile"].(map[string]interface{})["id"].(string),
		"exp":      time.Now().Add(time.Second * time.Duration(SessionExpiresIn)).Unix(),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := jwtToken.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to sign JWT: " + err.Error()})
		return
	}

	setEnvCookie(c, "mc_auth_token", tokenResponse.AccessToken, tokenResponse.ExpiresIn)
	setEnvCookie(c, "mc_jwt", token, tokenResponse.ExpiresIn)

	c.Redirect(302, redirectURI)
}

func MinecraftLogoutHandler(c *gin.Context) {
	redirect_uri := c.Query("redirect_uri")
	if redirect_uri == "" {
		redirect_uri = "https://sbm.gg/"
	}

	if !isValidRedirect(redirect_uri) {
		c.JSON(400, gin.H{"error": "Invalid redirect URI"})
		return
	}

	setEnvCookie(c, "mc_auth_token", "", -1)
	setEnvCookie(c, "mc_jwt", "", -1)

	c.Redirect(302, redirect_uri)
}
