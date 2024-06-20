package exporter

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/5GSEC/nimbus/pkg/adapter/nimbus-apilog/types"
)

// HTTPEx Global reference
var HTTPEx *HTTPExporter

// init Function
func init() {
	HTTPEx = NewHTTPExporter()
}

// HTTPExporter Structure
type HTTPExporter struct {
	dataChan chan interface{}
	stopChan chan struct{}
}

// NewHTTPExporter Function
func NewHTTPExporter() *HTTPExporter {
	return &HTTPExporter{
		dataChan: make(chan interface{}),
		stopChan: make(chan struct{}),
	}
}

// InsertHTTPLog Function
func (hx *HTTPExporter) InsertHTTPLog(log interface{}) error {
	switch log.(type) {
	case *types.HTTPRequest, *types.HTTPResponse:
		hx.dataChan <- log
	default:
		return errors.New("invalid type")
	}

	return nil
}

// RunExporter method
func (hx *HTTPExporter) RunExporter(stopChan chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		hx.exporterRoutine(stopChan)
	}()
}

// exporterRoutine method
func (hx *HTTPExporter) exporterRoutine(stopChan chan struct{}) {
	for {
		select {
		case httpLog := <-hx.dataChan:
			go func() {
				ProcessHTTPEvent(httpLog)
			}()
		case <-stopChan:
			log.Println("HTTP Exporter stopped")
			return
		}
	}
}

// processHTTPEvent Function
// @todo remove this
func ProcessHTTPEvent(httpLog interface{}) {
	switch httpLog.(type) {
	case *types.HTTPRequest:
		httpRequest := httpLog.(*types.HTTPRequest)
		fmt.Println("-------------------------")
		log.Printf("[HTTP] Request: %s -> %s, [%s] %s %s", httpRequest.Src.ToString(), httpRequest.Dst.ToString(),
			httpRequest.Method, httpRequest.Path, httpRequest.Version)
	case *types.HTTPResponse:
		httpResponse := httpLog.(*types.HTTPResponse)
		fmt.Println("-------------------------")
		log.Printf("[HTTP] Response: %s -> %s, [%d] %s", httpResponse.Src.ToString(), httpResponse.Dst.ToString(),
			httpResponse.ResponseCode, httpResponse.Version)
	}
}
