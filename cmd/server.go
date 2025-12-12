/*
Copyright © 2025 Simon HUET

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/simonnix/fbrtls/pkg/fbr"
	"github.com/simonnix/fbrtls/pkg/services"
)

var enableClientAuth bool
var enableClientAuthCrl bool
var enableClientAuthCrlFetch bool

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Runs the Fiber server",
	Long: `It runs a Fiber server with just a Get("/") handler which returns "Hello World".

The server can be configured with mTLS (--auth), CRL checking (--crl) and CRL fetching.`,
	Run: func(cmd *cobra.Command, args []string) {

		s := []services.Service{}

		var cfg *services.ConfigTLS

		if viper.GetBool("path") {
			cfg = services.NewConfig(viper.Sub("tls.path"))
		} else {
			cfg = services.NewConfig(viper.Sub("tls.value"))
		}

		mainCfg := fbr.DefaultListenConfig()

		tlsProvider := &fbr.ServerCertificateProvider{
			CertificateChain: cfg.Server,
		}

		if enableClientAuth {
			cert := cfg.Intermediate
			if !enableClientAuthCrl {
				tlsProvider.Customizer = &fbr.MTLSServerCertificateCustomizer{
					ClientCertificate: cert,
				}
			} else {
				tlsProvider.Customizer = &fbr.MTLSWithCRLServerCertificateCustomizer{
					ClientCertificate:   cert,
					RevocationList:      cfg.Crl,
					FetchRevocationList: enableClientAuthCrlFetch,
				}
			}
		}
		mainCfg.TLSProvider = tlsProvider

		if enableClientAuthCrl && enableClientAuthCrlFetch {
			s = append(s, services.Crl{Crl: cfg.Crl}.New(":"+viper.GetString("services.crl.port"), fbr.DefaultListenConfig()))
		}

		main := services.Hello{}.New(":"+viper.GetString("services.hello.port"), mainCfg)
		s = append(s, main)

		wg := sync.WaitGroup{}
		for _, service := range s {
			service.Run(&wg)
		}
		wg.Wait()
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().BoolVar(&enableClientAuth, "auth", false, "Enable mTLS authentication")
	serverCmd.Flags().BoolVar(&enableClientAuthCrl, "crl", false, "Enable CRL checking. Require '--auth'.")
	serverCmd.Flags().BoolVar(&enableClientAuthCrlFetch, "fetch", false, "Enable CRL fetching. Require '--auth' and '--crl'")
}
