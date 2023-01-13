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
	"strings"
	"sync"

	"go.bytebuilders.dev/lib-selfhost/client"
	"go.bytebuilders.dev/license-verifier/info"

	"github.com/cloudflare/cloudflare-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/pkg/errors"
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

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func NewCmdRun(ctx context.Context) *cobra.Command {
	var (
		addr             = ":8000"
		metricsAddr      = ":8080"
		apiServerAddress = ""
		debug            = false
	)
	cmd := &cobra.Command{
		Use:               "run",
		Short:             "Launch a Cloudflare DNS Proxy server",
		Long:              "Launch a Cloudflare DNS Proxy server",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			klog.Infof("Starting binary version %s+%s ...", v.Version.Version, v.Version.CommitHash)

			return run(ctx, addr, metricsAddr, apiServerAddress, debug)
		},
	}
	cmd.Flags().StringVar(&addr, "listen", addr, "Listen address.")
	cmd.Flags().StringVar(&metricsAddr, "metrics-addr", metricsAddr, "The address the metric endpoint binds to.")
	cmd.Flags().StringVar(&apiServerAddress, "api-server-addr", apiServerAddress, "The API server address")
	cmd.Flags().BoolVar(&debug, "debug", debug, "If true, dumps proxied request and responses")

	return cmd
}

func run(ctx context.Context, addr, metricsAddr, apiServerAddress string, debug bool) error {
	c, err := cloudflare.NewWithAPIToken(os.Getenv("CLOUDFLARE_API_TOKEN"))
	if err != nil {
		return err
	}
	target, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}

	authEndpoint, err := info.APIServerAddress(apiServerAddress)
	if err != nil {
		return err
	}
	authEndpoint.Path = path.Join(authEndpoint.Path, "/api/v1/ace-installer/installer-meta")

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = cloudflareTransport{
		apiToken:     c.APIToken,
		authEndpoint: authEndpoint.String(),
		debug:        debug,
	}

	r := prometheus.NewRegistry()
	r.MustRegister(httpRequestsTotal)
	r.MustRegister(httpRequestDuration)
	r.MustRegister(version)

	router := chi.NewRouter()
	// router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.HandleFunc("/*", promhttp.InstrumentHandlerDuration(
		httpRequestDuration,
		promhttp.InstrumentHandlerCounter(httpRequestsTotal, proxy),
	))
	srv := http.Server{
		Addr:    addr,
		Handler: router,
	}
	go func() {
		log.Printf("API server listening at http://%s", addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			klog.ErrorS(err, "HTTP server ListenAndServe failed")
		}
	}()

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("OK"))
		}))
		mux.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
		metricsServer := http.Server{
			Addr:    metricsAddr,
			Handler: mux,
		}
		log.Printf("Telemetry server listening at http://%s", metricsAddr)
		if err := metricsServer.ListenAndServe(); err != http.ErrServerClosed {
			klog.ErrorS(err, "Metrics server ListenAndServe failed")
		}
	}()

	<-ctx.Done()
	return srv.Shutdown(ctx)
}

type cloudflareTransport struct {
	authEndpoint string
	apiToken     string
	debug        bool
}

func (rt cloudflareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.debug {
		if data, err := httputil.DumpRequestOut(req, true); err == nil {
			fmt.Println("REQUEST: >>>>>>>>>>>>>>>>>>>>>>>")
			fmt.Println(string(data))
		}
	}

	meta, err := rt.check(req)
	if err != nil {
		cr := cloudflare.Response{
			Success: false,
			Errors:  []cloudflare.ResponseInfo{{Message: err.Error()}},
		}
		data, err := json.Marshal(cr)
		if err != nil {
			return nil, err
		}
		if rt.debug {
			fmt.Println("RESPONSE_403: >>>>>>>>>>>>>>>>>>>>>>>")
			fmt.Println(string(data))
		}
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(bytes.NewReader(data)),
		}, nil
	}

	if rt.debug {
		md, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			return nil, err
		}
		fmt.Println("INSTALLER_METADATA: >>>>>>>>>>>>>>>>>>>>>>>")
		fmt.Println(string(md))
	}

	req.Host = ""
	req.Header.Set("Authorization", "Bearer "+rt.apiToken)

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if rt.debug {
		if data, err := httputil.DumpResponse(resp, false); err == nil {
			fmt.Println("RESPONSE: >>>>>>>>>>>>>>>>>>>>>>>")
			fmt.Println(string(data))
		}
	}
	return resp, nil
}

func (rt cloudflareTransport) check(req *http.Request) (*client.InstallerMetadata, error) {
	if req.Method != http.MethodGet &&
		req.Method != http.MethodPost &&
		req.Method != http.MethodDelete {
		return nil, errors.Errorf("unsupported HTTP Method %s", req.Method)
	}

	meta, err := client.GetInstallerMetadata(rt.authEndpoint, req.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}

	/*
		"GET http://dns-proxy.appscode.ninja/zones/${zoneID}/dns_records?page=1
		"GET http://dns-proxy.appscode.ninja/zones?per_page=50

		// Authorize
		"DELETE http://dns-proxy.appscode.ninja/zones/${zoneID}/dns_records/${recordID}
		"POST http://dns-proxy.appscode.ninja/zones/${zoneID}/dns_records
	*/
	if (req.Method == http.MethodPost || req.Method == http.MethodDelete) &&
		req.Body != nil &&
		req.Body != http.NoBody {
		buf := bufferPool.Get().(*bytes.Buffer)
		defer bufferPool.Put(buf)
		buf.Reset()

		// xref: https://github.com/golang/go/blob/76d39ae3499238ac7efb731f4f4cd47b1b3288ab/src/net/http/httputil/dump.go#L20-L38
		if _, err = buf.ReadFrom(req.Body); err != nil {
			return nil, err
		}
		if err = req.Body.Close(); err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))

		var record cloudflare.DNSRecord
		if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
			return nil, err
		}
		if record.Type == "A" ||
			record.Type == "AAAA" ||
			record.Type == "CNAME" {
			ok := record.Name == meta.HostedDomain || strings.HasSuffix(record.Name, "."+meta.HostedDomain)
			if !ok {
				fmt.Printf("authorized to modify record for domain %s but modifying %s\n", meta.HostedDomain, record.Name)
				return nil, errors.Errorf("authorized to modify record for domain %s but modifying %s", meta.HostedDomain, record.Name)
			}
		}
	}
	return meta, nil
}
