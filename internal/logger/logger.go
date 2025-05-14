package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New returns a console-encoded (colored) zap.Logger at the given level.
func New(level string) *zap.Logger {
	cfg := zap.NewDevelopmentConfig()
	// allow override from env / config
	if err := cfg.Level.UnmarshalText([]byte(level)); err != nil {
		cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}
	// ensure colored levels
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	log, _ := cfg.Build(zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	return log
}
