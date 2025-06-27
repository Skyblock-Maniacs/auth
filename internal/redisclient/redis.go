package redisclient

import (
	"context"

	"github.com/redis/go-redis/v9"
)

type RedisClientOptions struct {
	Addr     string
	Password string
	Port     string
	User     string
}

func Connect(opts *RedisClientOptions) (*redis.Client, context.Context, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     opts.Addr + ":" + opts.Port,
		Password: opts.Password,
		Username: opts.User,
		DB:       0,
	})

	var ctx = context.Background()

	// Test the connection
	if _, err := client.Ping(ctx).Result(); err != nil {
		return nil, ctx, err
	}
	return client, ctx, nil
}
