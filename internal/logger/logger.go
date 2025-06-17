package logger

import (
	"log"
	"os"
)

var (
	Info  *log.Logger
	Debug *log.Logger
	Error *log.Logger
)

func init() {
	Info = log.New(os.Stdout, "[INFO] ", log.LstdFlags)
	Debug = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)
	Error = log.New(os.Stderr, "[ERROR] ", log.LstdFlags)
}
