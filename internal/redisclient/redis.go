package redisclient

import (
	"context"

	"github.com/redis/go-redis/v9"
)

func Connect(uri string, password string) (*redis.Client, context.Context, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     uri,
		Password: password, // leave empty if none
		DB:       0,       // default DB
	})

	var ctx = context.Background()

	// Test the connection
	if _, err := client.Ping(ctx).Result(); err != nil {
		return nil, ctx, err
	}
	return client, ctx, nil
}
