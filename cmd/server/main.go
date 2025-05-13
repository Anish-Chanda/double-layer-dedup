package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"go.uber.org/zap"

	"github.com/Anish-Chanda/double-layer-dedup/internal/config"
	"github.com/Anish-Chanda/double-layer-dedup/internal/db"
	"github.com/Anish-Chanda/double-layer-dedup/internal/dsde"
	"github.com/Anish-Chanda/double-layer-dedup/internal/logger"
	"github.com/Anish-Chanda/double-layer-dedup/internal/split"
	"github.com/Anish-Chanda/double-layer-dedup/internal/storage"
)

func loadAWSConfig(region string) (aws.Config, error) {
	opts := []func(*awsConfig.LoadOptions) error{
		awsConfig.WithRegion(region),
	}
	if ep := os.Getenv("AWS_ENDPOINT_URL"); ep != "" {
		resolver := aws.EndpointResolverFunc(
			func(service, region string) (aws.Endpoint, error) {
				return aws.Endpoint{URL: ep, SigningRegion: region}, nil
			},
		)
		opts = append(opts, awsConfig.WithEndpointResolver(resolver))
	}
	return awsConfig.LoadDefaultConfig(context.Background(), opts...)
}

func main() {
	// 1) Load environment variables from .env
	_ = godotenv.Load()

	// 2) Load application config
	cfg, err := config.Load()
	if err != nil {
		panic(fmt.Errorf("config load: %w", err))
	}

	// 3) Apply database migrations
	m, err := migrate.New(
		"file://"+os.Getenv("PWD")+"/migrations",
		cfg.PostgresDSN,
	)
	if err != nil {
		panic(fmt.Errorf("migrate init: %w", err))
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		panic(fmt.Errorf("migrate up: %w", err))
	}

	// 4) Initialize logger
	log := logger.New(cfg.LogLevel)
	defer log.Sync()

	// 5) Load AWS configuration (points at LocalStack if AWS_ENDPOINT_URL is set)
	awsCfg, err := loadAWSConfig(cfg.AWSRegion)
	if err != nil {
		log.Fatal("AWS config", zap.Error(err))
	}

	// 6) Initialize AWS clients
	kmsClient := kms.NewFromConfig(awsCfg)

	// 7) Initialize infra clients
	storeClient, err := storage.NewWithClient(cfg.S3Bucket, awsCfg)
	if err != nil {
		log.Fatal("S3 init", zap.Error(err))
	}
	dbClient, err := db.New(cfg)
	if err != nil {
		log.Fatal("DB init", zap.Error(err))
	}

	// 8) Build DSDE service
	fg := split.NewFG([]uint64{1, 3, 5}, []uint64{0, 0, 0})
	svc := dsde.NewService(fg, 3, kmsClient, cfg.KMSKeyID, dbClient, storeClient)

	// 9) Configure HTTP router
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	r.Post("/files", func(w http.ResponseWriter, r *http.Request) {
		owner := r.Header.Get("X-Owner-ID")
		filename := r.Header.Get("X-Filename")
		if owner == "" || filename == "" {
			http.Error(w, "missing owner or filename headers", http.StatusBadRequest)
			return
		}
		fileID, feaHash, dekShared, dekUser, err := svc.Upload(r.Context(), owner, filename, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp := map[string]string{
			"fileID":    fileID,
			"feaHash":   hex.EncodeToString(feaHash),
			"dekShared": hex.EncodeToString(dekShared),
			"dekUser":   hex.EncodeToString(dekUser),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	r.Get("/files/{fileID}", func(w http.ResponseWriter, r *http.Request) {
		owner := r.Header.Get("X-Owner-ID")
		fileID := chi.URLParam(r, "fileID")
		if owner == "" {
			http.Error(w, "missing owner header", http.StatusBadRequest)
			return
		}
		rc, err := svc.Download(r.Context(), owner, fileID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rc.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		io.Copy(w, rc)
	})

	// 10) Start HTTP server
	log.Info("starting server", zap.String("addr", cfg.ServerAddr))
	if err := http.ListenAndServe(cfg.ServerAddr, r); err != nil {
		log.Fatal("server failed", zap.Error(err))
	}
}
