package logging

import (
	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func init() {
	log = logrus.New()

	// Set log output format
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	log.SetFormatter(customFormatter)
}

// InitLogger initializes the global logger with the specified log level
func InitLogger(logLevel logrus.Level) {
	log.SetLevel(logLevel)
}

// GetLogger returns the global logger instance
func GetLogger() *logrus.Logger {
	return log
}
