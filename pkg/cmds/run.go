/*
Copyright AppsCode Inc. and Contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmds

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/cloudflare/cloudflare-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	v "gomodules.xyz/x/version"
	"k8s.io/klog/v2"
)

var (
	version = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "version",
		Help: "Version information about this binary",
		ConstLabels: map[string]string{
			"version": v.Version.Version,
		},
	})

	httpRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Count of all HTTP requests",
	}, []string{"code", "method"})

	httpRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "http_request_duration_seconds",
		Help: "Duration of all HTTP requests",
	}, []string{"code", "handler", "method"})
)

func NewCmdRun(ctx context.Context) *cobra.Command {
	var (
		addr        string = ":8000"
		metricsAddr string = ":8080"
	)
	cmd := &cobra.Command{
		Use:               "run",
		Short:             "Launch a Cloudflare DNS Proxy server",
		Long:              "Launch a Cloudflare DNS Proxy server",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			klog.Infof("Starting binary version %s+%s ...", v.Version.Version, v.Version.CommitHash)

			return run(ctx, addr, metricsAddr)
		},
	}
	cmd.Flags().StringVar(&addr, "listen", addr, "Listen address.")
	cmd.Flags().StringVar(&metricsAddr, "metrics-addr", metricsAddr, "The address the metric endpoint binds to.")

	return cmd
}

func run(ctx context.Context, addr, metricsAddr string) error {
	api, err := cloudflare.NewWithAPIToken(os.Getenv("CLOUDFLARE_API_TOKEN"))
	if err != nil {
		return err
	}
	target, _ := url.Parse(api.BaseURL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	d := proxy.Director
	proxy.Director = func(req *http.Request) {
		d(req)
		req.Host = ""
		req.Header.Set("Authorization", "Bearer "+api.APIToken)
	}

	r := prometheus.NewRegistry()
	r.MustRegister(httpRequestsTotal)
	r.MustRegister(httpRequestDuration)
	r.MustRegister(version)

	log.Printf("Listening at http://%s", addr)
	srv := http.Server{
		Addr: addr,
		Handler: promhttp.InstrumentHandlerDuration(
			httpRequestDuration,
			promhttp.InstrumentHandlerCounter(httpRequestsTotal, proxy),
		),
	}
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			klog.ErrorS(err, "HTTP server ListenAndServe failed")
		}
	}()

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
		metricsServer := http.Server{
			Addr:    metricsAddr,
			Handler: mux,
		}
		if err := metricsServer.ListenAndServe(); err != http.ErrServerClosed {
			klog.ErrorS(err, "Metrics server ListenAndServe failed")
		}
	}()

	<-ctx.Done()
	return srv.Shutdown(ctx)
}
