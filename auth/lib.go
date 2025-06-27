package auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Skyblock-Maniacs/auth/internal/logger"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var allowedDomains = []string{
	"sbm.gg",
}

var allowedLocalhosts = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
}

const (
	DiscordTokenExpiresIn        = 60 * 60 * 24 * 7          // 7 days
	DiscordRefreshTokenExpiresIn = 60 * 60 * 24 * 7          // 7 days
	SessionExpiresIn             = 60 * 60 * 24 * 7          // 7 days
)

type SessionData struct {
	UserID     string `json:"user_id"`
	Username   string `json:"username"`
	AvatarHash string `json:"avatar_hash"`
}

func isValidRedirect(redirectURI string) bool {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme != "https" && u.Scheme != "http" {
		return false
	}

	host := u.Hostname()

	if allowedLocalhosts[host] {
		return true
	}

	if net.ParseIP(host) != nil && !allowedLocalhosts[host] {
		return false
	}

	for _, domain := range allowedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

func generateJWT(session SessionData) (string, error) {
	claims := jwt.MapClaims{
		"user_id":     session.UserID,
		"username":    session.Username,
		"avatar_hash": session.AvatarHash,
		"exp":         time.Now().Add(time.Duration(SessionExpiresIn) * time.Second).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func decodeJwt(tokenString string) (*SessionData, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if claims, ok := token.Claims.(*jwt.MapClaims); ok && token.Valid {
		session := &SessionData{
			UserID:     (*claims)["user_id"].(string),
			Username:   (*claims)["username"].(string),
			AvatarHash: (*claims)["avatar_hash"].(string),
		}
		return session, nil
	}

	return nil, fmt.Errorf("invalid JWT claims")
}

func setEnvCookie(c *gin.Context, name, value string, maxAge int) {
	host := c.Request.Host

	if strings.Contains(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
		c.SetCookie(name, value, maxAge, "/", "", false, true)
		return
	}

	c.SetCookie(name, value, maxAge, "/", ".sbm.gg", true, true)
}

func setDiscordCookies(form url.Values, c *gin.Context) (accessToken string, jwtToken string, err error) {
	logger.Debug.Printf("Setting Discord cookies with form: %v", form)
	req, err := http.NewRequest(http.MethodPost, DiscordAPIBaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("failed to create request for discord token: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to get discord token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("discord token request failed with status: %s", resp.Status)
	}

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", "", fmt.Errorf("failed to decode discord token response: %w", err)
	}

	user, err := getDiscordUserWithAccessToken(tokenResponse.AccessToken)
	if err != nil {
		return "", "", fmt.Errorf("failed to get discord user info: %w", err)
	}

	session := SessionData{
		UserID:     user["id"].(string),
		Username:   user["username"].(string),
		AvatarHash: user["avatar"].(string),
	}

	jwtToken, err = generateJWT(session)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	setEnvCookie(c, "sbm_jwt", jwtToken, SessionExpiresIn)
	setEnvCookie(c, "discord_access_token", tokenResponse.AccessToken, DiscordTokenExpiresIn)
	setEnvCookie(c, "discord_refresh_token", tokenResponse.RefreshToken, DiscordRefreshTokenExpiresIn)
	return tokenResponse.AccessToken, jwtToken, nil
}

func getDiscordUserWithAccessToken(access string) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, DiscordAPIBaseURL+"/users/@me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: %s", resp.Status)
	}
	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}
	return user, nil
}

func getDiscordUserSbmGuildRoles(access string) ([]string, error) {
	url := fmt.Sprintf("%s/users/@me/guilds/%s/member", DiscordAPIBaseURL, os.Getenv("DISCORD_GUILD_ID"))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user roles: %s", resp.Status)
	}
	var member map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&member); err != nil {
		return nil, fmt.Errorf("failed to decode member info: %w", err)
	}
	roles, ok := member["roles"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("roles not found in member info")
	}
	roleStrings := make([]string, len(roles))
	for i, role := range roles {
		roleStrings[i] = role.(string)
	}
	return roleStrings, nil
}
