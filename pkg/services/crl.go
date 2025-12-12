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
package services

import (
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/simonnix/fbrtls/pkg/fbr"
)

type Crl struct {
	*fbr.App
	Crl    string
	listen string
	config fbr.ListenConfig
}

func (crl Crl) New(addr string, config fbr.ListenConfig) *Crl {
	crl.listen = addr
	crl.config = config
	crl.App = fbr.NewApp()
	crl.App.Use(logger.New())

	crl.App.Get("/crl.pem", func(c fiber.Ctx) error {
		return c.SendString(crl.Crl)
	})

	return &crl
}

// Run implements Service.
func (crl *Crl) Run(wg *sync.WaitGroup) {
	wg.Go(func() {
		crl.Listen(crl.listen, crl.config)
	})
	time.Sleep(200 * time.Millisecond)
}

var _ Service = &Crl{}
