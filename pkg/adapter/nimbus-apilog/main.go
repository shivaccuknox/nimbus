// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Nimbus

package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/5GSEC/nimbus/pkg/adapter/nimbus-apilog/bpf"
	"github.com/5GSEC/nimbus/pkg/adapter/nimbus-apilog/manager"
)

func main() {
	ctrl.SetLogger(zap.New())
	logger := ctrl.Log

	ctx, cancelFunc := context.WithCancel(context.Background())
	ctrl.LoggerInto(ctx, logger)

	go func() {
		termChan := make(chan os.Signal)
		signal.Notify(termChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		<-termChan
		logger.Info("Shutdown signal received, waiting for all workers to finish")
		cancelFunc()
	}()

	// setup up eBPF handlers
	// init eBPF Handler
	bpf.Bh = bpf.NewBpfHandler()
	bpf.TCH = bpf.NewTCHandler()

	// Run eBPF Handler
	// TODO: We need to pass the context to these handlers, and these handlers should watch
	// for the close of done channel. The below waitgroup is needed for this routine to know
	// when the handlers are done
	var wg *sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		bpf.Bh.Run()
	}()

	go func() {
		defer wg.Done()
		bpf.TCH.RunWatchRoutine()
	}()

	// closer
	go func() {
		wg.Wait()
		logger.Info("All workers finished, shutting down")
	}()

	logger.Info("NetworkPolicy adapter started")
	manager.Run(ctx)
}
