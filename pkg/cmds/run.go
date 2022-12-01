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
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	v "gomodules.xyz/x/version"
	"k8s.io/klog/v2"
)

func NewCmdRun(ctx context.Context) *cobra.Command {
	var listenAddress string
	cmd := &cobra.Command{
		Use:               "run",
		Short:             "Launch a Cloudflare DNS Proxy server",
		Long:              "Launch a Cloudflare DNS Proxy server",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			klog.Infof("Starting binary version %s+%s ...", v.Version.Version, v.Version.CommitHash)

			return run(ctx, listenAddress)
		},
	}
	cmd.Flags().StringVar(&listenAddress, "listen", ":8000", "Listen address.")

	return cmd
}

func run(ctx context.Context, listenAddress string) error {
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

	log.Printf("Listening at http://%s", listenAddress)
	srv := http.Server{
		Addr:    listenAddress,
		Handler: proxy,
	}
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return errors.Wrap(err, "HTTP server ListenAndServe failed")
	}
	<-ctx.Done()
	return srv.Shutdown(ctx)
}
