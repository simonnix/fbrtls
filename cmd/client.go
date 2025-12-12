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
	//"github.com/gofiber/fiber/v3/client"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/simonnix/fbrtls/pkg/fbr"
	"github.com/simonnix/fbrtls/pkg/services"
)

var revoked bool

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Run a GET command to the server with TLS parameters certificate",
	Long: `Run a GET command to the server with the "client" certificate and the Root CA.

You can use the '--revoked' flag to use the "revoked" certificate which is a valid certificate
but will be rejected if the server is running with the '--crl' flag.

It can be configured with TLS certificates from values (certificates in config file) or paths
(also defined in config file, with --path flag).`,
	Run: func(cmd *cobra.Command, args []string) {
		var cfg *services.ConfigTLS

		if viper.GetBool("path") {
			cfg = services.NewConfig(viper.Sub("tls.path"))
		} else {
			cfg = services.NewConfig(viper.Sub("tls.value"))
		}

		cert := cfg.Client
		if revoked {
			fmt.Println("hello: Using the revoked certificate")
			cert = cfg.Revoked
		}

		cc := fbr.NewClient()
		cc.SetTLSProvider(&fbr.ClientCertificateProvider{
			CertificateChain: cert,
			RootCertificate:  cfg.Root,
		})

		url := "https://localhost:" + viper.GetString("services.hello.port")
		if resp, err := cc.Get(url); err != nil {
			fmt.Printf("hello: %s\n", err.Error())
		} else {
			fmt.Printf("hello: %s\n", resp.String())
		}
	},
}

func init() {
	rootCmd.AddCommand(clientCmd)

	clientCmd.Flags().BoolVar(&revoked, "revoked", false, "Use the revoked certificate")
}
