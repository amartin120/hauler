package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"hauler.dev/go/hauler/internal/flags"
	"hauler.dev/go/hauler/pkg/consts"
)

// NewFile returns a fileserver
// TODO: Better configs
func NewFile(ctx context.Context, cfg flags.ServeFilesOpts) (Server, error) {
	r := mux.NewRouter()
	r.PathPrefix("/").Handler(handlers.LoggingHandler(os.Stdout, http.StripPrefix("/", http.FileServer(http.Dir(cfg.RootDir)))))
	if cfg.RootDir == "" {
		cfg.RootDir = "."
	}

	if cfg.Port == 0 {
		cfg.Port = consts.DefaultFileserverPort
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = consts.DefaultFileserverTimeout
	}

	srv := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		WriteTimeout: time.Duration(cfg.Timeout) * time.Second,
		ReadTimeout:  time.Duration(cfg.Timeout) * time.Second,
	}

	return srv, nil
}
