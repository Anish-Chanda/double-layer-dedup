package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	ServerAddr string
	LogLevel   string

	AWSRegion   string
	KMSKeyID    string
	S3Bucket    string
	PostgresDSN string
}

func Load() (*Config, error) {
	viper.SetEnvPrefix("DSDE")
	viper.AutomaticEnv()

	viper.SetDefault("SERVER_ADDR", ":8080")
	viper.SetDefault("LOG_LEVEL", "info")

	cfg := &Config{
		ServerAddr: viper.GetString("SERVER_ADDR"),
		LogLevel:   viper.GetString("LOG_LEVEL"),

		AWSRegion:   viper.GetString("AWS_REGION"),
		KMSKeyID:    viper.GetString("KMS_KEY_ID"),
		S3Bucket:    viper.GetString("S3_BUCKET"),
		PostgresDSN: viper.GetString("POSTGRES_DSN"),
	}
	return cfg, nil
}
