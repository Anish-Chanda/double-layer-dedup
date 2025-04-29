package main

import (
	"net/http"

	"github.com/Anish-Chanda/double-layer-dedup/cmd/internal/config"
	"github.com/Anish-Chanda/double-layer-dedup/cmd/internal/logger"
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

	// TODO: wire up chi router, health & file endpoints
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	if err := http.ListenAndServe(cfg.ServerAddr, nil); err != nil {
		log.Fatal("server failed", zap.Error(err))
	}
}
