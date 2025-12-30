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
	"fmt"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/simonnix/fbrtls/pkg/fbr"
)

type Hello struct {
	*fbr.App
	listen string
	config fbr.ListenConfig
}

func (main Hello) New(addr string, config fbr.ListenConfig) *Hello {
	main.listen = addr
	main.config = config

	main.App = fbr.NewApp()
	main.Use(logger.New())

	main.Get("/", func(c fiber.Ctx) error {
		return c.SendString("Hello World")
	})

	return &main
}

// Run implements Service.
func (main *Hello) Run(wg *sync.WaitGroup) {
	wg.Go(func() {
		if err := main.Listen(main.listen, main.config); err != nil {
			fmt.Printf("Main error: %s", err.Error())
		}
	})
	time.Sleep(200 * time.Millisecond)
}

var _ Service = &Hello{}
