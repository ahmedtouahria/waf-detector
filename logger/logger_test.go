package logger

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name   string
		debug  bool
		silent bool
		level  logrus.Level
	}{
		{"normal", false, false, logrus.InfoLevel},
		{"debug", true, false, logrus.DebugLevel},
		{"silent", false, true, logrus.ErrorLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Init(tt.debug, tt.silent)
			if Log == nil {
				t.Fatal("Logger not initialized")
			}
			if Log.GetLevel() != tt.level {
				t.Errorf("Log level = %v, want %v", Log.GetLevel(), tt.level)
			}
		})
	}
}

func TestLoggingFunctions(t *testing.T) {
	Init(false, true) // Silent mode to avoid output during tests
	// Test that these don't panic
	Debug("test")
	Debugf("test %s", "formatted")
	Info("test")
	Infof("test %s", "formatted")
	Warn("test")
	Warnf("test %s", "formatted")
	Error("test")
	Errorf("test %s", "formatted")
}
