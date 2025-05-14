package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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

func loadAWSConfig(region string) (cfg aws.Config, err error) {
	opts := []func(*awsConfig.LoadOptions) error{awsConfig.WithRegion(region)}
	if ep := os.Getenv("AWS_ENDPOINT_URL"); ep != "" {
		res := aws.EndpointResolverFunc(
			func(service, region string) (aws.Endpoint, error) {
				return aws.Endpoint{URL: ep, SigningRegion: region}, nil
			})
		opts = append(opts, awsConfig.WithEndpointResolver(res))
	}
	return awsConfig.LoadDefaultConfig(context.Background(), opts...)
}

type zapLoggerAdapter struct {
	logger *zap.Logger
}

func (l *zapLoggerAdapter) Print(v ...interface{}) {
	l.logger.Sugar().Info(v...)
}

func main() {
	// parse our --stats flag
	stats := flag.Bool("stats", false, "print per-upload dedupe statistics")
	flag.Parse()

	_ = godotenv.Load()
	cfg, err := config.Load()
	if err != nil {
		panic(fmt.Errorf("config load: %w", err))
	}

	// apply migrations
	m, err := migrate.New(
		"file://"+os.Getenv("PWD")+"/migrations",
		cfg.PostgresDSN,
	)
	if err != nil {
		panic(err)
	}
	_ = m.Up() // ignore ErrNoChange

	// console-friendly logger
	log := logger.New(cfg.LogLevel)
	defer log.Sync()
	zap.ReplaceGlobals(log)

	// aws + infra clients
	awsCfg, err := loadAWSConfig(cfg.AWSRegion)
	if err != nil {
		zap.L().Fatal("AWS config", zap.Error(err))
	}
	kmsClient := kms.NewFromConfig(awsCfg)
	storeClient, err := storage.NewWithClient(cfg.S3Bucket, awsCfg)
	if err != nil {
		zap.L().Fatal("S3 init", zap.Error(err))
	}
	dbClient, err := db.New(cfg)
	if err != nil {
		zap.L().Fatal("DB init", zap.Error(err))
	}

	// our DSDE service
	fg := split.NewFG([]uint64{1, 3, 5}, []uint64{0, 0, 0})
	svc := dsde.NewService(fg, 3, kmsClient, cfg.KMSKeyID, dbClient, storeClient, *stats)

	// router w/ pretty request logs
	r := chi.NewRouter()
	r.Use(middleware.RequestID)

	zapAdapter := &zapLoggerAdapter{logger: zap.L()}
	r.Use(middleware.RequestLogger(&middleware.DefaultLogFormatter{Logger: zapAdapter, NoColor: false}))
	r.Use(middleware.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
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
			"feaHash":   fmt.Sprintf("%x", feaHash),
			"dekShared": fmt.Sprintf("%x", dekShared),
			"dekUser":   fmt.Sprintf("%x", dekUser),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	r.Get("/files/{fileID}", func(w http.ResponseWriter, r *http.Request) {
		owner := r.Header.Get("X-Owner-ID")
		if owner == "" {
			http.Error(w, "missing owner header", http.StatusBadRequest)
			return
		}
		rc, err := svc.Download(r.Context(), owner, chi.URLParam(r, "fileID"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rc.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		io.Copy(w, rc)
	})

	r.Get("/admin/s3-list", func(w http.ResponseWriter, r *http.Request) {
		keys, err := storeClient.ListKeys(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(keys)
	})

	zap.L().Info("starting server", zap.String("addr", cfg.ServerAddr))
	http.ListenAndServe(cfg.ServerAddr, r)
}
