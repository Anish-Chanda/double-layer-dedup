package main

import (
	"context"
	"net/http"

	"github.com/Anish-Chanda/double-layer-dedup/cmd/awschecks"
	"github.com/Anish-Chanda/double-layer-dedup/internal/config"
	"github.com/Anish-Chanda/double-layer-dedup/internal/logger"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"go.uber.org/zap"
)

func main() {
	// load config
	cfg, err := config.Load()
	if err != nil {
		panic("failed to load config: " + err.Error())
	}

	// init logger
	log := logger.New(cfg.LogLevel)
	defer log.Sync()

	log.Info("Starting DSDE Dedup API", zap.String("addr", cfg.ServerAddr))

	// check aws connection
	awsCfg, _ := awsConfig.LoadDefaultConfig(context.Background(),
		awsConfig.WithRegion(cfg.AWSRegion))
	account, err := awschecks.VerifyAWS(context.Background(), awsCfg)
	if err != nil {
		panic("AWS not configured: " + err.Error())
	}
	log.Info("Running under AWS account", zap.String("account", account))

	// TODO: wire up chi router, health & file endpoints
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	if err := http.ListenAndServe(cfg.ServerAddr, nil); err != nil {
		log.Fatal("server failed", zap.Error(err))
	}
}
