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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"time"

	"go.bytebuilders.dev/license-verifier/info"

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
	}, []string{"code", "method"})
)

func NewCmdRun(ctx context.Context) *cobra.Command {
	var (
		addr        = ":8000"
		metricsAddr = ":8080"
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
	target, err := url.Parse(api.BaseURL)
	if err != nil {
		return err
	}

	aceInstallerURL := info.APIServerAddress()
	aceInstallerURL.Path = path.Join(aceInstallerURL.Path, "/api/v1/ace-installer/installer-meta")

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = cloudflareTransport{
		cfApiToken:      api.APIToken,
		aceInstallerURL: aceInstallerURL.String(),
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

type cloudflareTransport struct {
	aceInstallerURL string
	cfApiToken      string
}

func (rt cloudflareTransport) fetchInstallerMetadata(authHeader string) (InstallerMetadata, error) {
	req, err := http.NewRequest(http.MethodGet, rt.aceInstallerURL, nil)
	if err != nil {
		return InstallerMetadata{}, err
	}

	req.Header.Set("Authorization", authHeader)
	fmt.Println(authHeader, rt.aceInstallerURL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return InstallerMetadata{}, err
	}

	meta := InstallerMetadata{}
	if err = json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return InstallerMetadata{}, err
	}

	return meta, nil
}

func (rt cloudflareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	meta, err := rt.fetchInstallerMetadata(req.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}

	req.Host = ""
	req.Header.Set("Authorization", "Bearer "+rt.cfApiToken)
	u, err := url.Parse(req.RequestURI)
	if err != nil {
		return nil, err
	}

	domain := u.Query().Get("name")

	if domain != meta.HostedURL {
		cr := cloudflare.Response{
			Success: false,
			Errors:  []cloudflare.ResponseInfo{{Message: "domain mismatch"}},
		}
		data, err := json.Marshal(cr)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(bytes.NewReader(data)),
		}, nil
	}
	return http.DefaultTransport.RoundTrip(req)
}

type InstallerMetadata struct {
	ID         string `json:"ID"`
	Domain     string `json:"domain"`
	HostedURL  string `json:"hostedURL"`
	OwnerID    int64  `json:"ownerID"`
	AuthorID   int64  `json:"authorID"`
	AuthorName string `json:"authorName,omitempty"`
	Production bool   `json:"production"`

	CreateTimestamp time.Time `json:"createTimestamp"`
	ExpiryTimestamp time.Time `json:"expiryTimestamp,omitempty"`
}
