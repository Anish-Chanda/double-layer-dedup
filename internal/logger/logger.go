package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func New(level string) *zap.Logger {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	if err := cfg.Level.UnmarshalText([]byte(level)); err != nil {
		// fallback to info
		cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}
	log, _ := cfg.Build()
	return log
}
