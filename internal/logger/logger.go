package logger

import (
	"log"
	"os"

	"github.com/fatih/color"
)

// Logger represents a custom logger with colorized output
type Logger struct {
	infoLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
	debug       bool
}

// New creates a new logger instance
func New(debug bool) *Logger {
	infoColor := color.New(color.FgGreen).SprintFunc()
	errorColor := color.New(color.FgRed).SprintFunc()
	debugColor := color.New(color.FgYellow).SprintFunc()

	return &Logger{
		infoLogger:  log.New(os.Stdout, infoColor("[INFO] "), log.LstdFlags|log.Lshortfile),
		errorLogger: log.New(os.Stderr, errorColor("[ERROR] "), log.LstdFlags|log.Lshortfile),
		debugLogger: log.New(os.Stdout, debugColor("[DEBUG] "), log.LstdFlags|log.Lshortfile),
		debug:       debug,
	}
}

// Info logs an info message
func (l *Logger) Info(format string, v ...interface{}) {
	l.infoLogger.Printf(format, v...)
}

// Error logs an error message
func (l *Logger) Error(format string, v ...interface{}) {
	l.errorLogger.Printf(format, v...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.debug {
		l.debugLogger.Printf(format, v...)
	}
}
