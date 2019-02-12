package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/contrib/ginrus"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var (
	version    = ""
	minversion = ""
)

func main() {
	app := cli.NewApp()
	app.Name = "fox-fake-gateway"
	app.Version = version + minversion

	app.Flags = []cli.Flag{
		cli.BoolFlag{Name: "debug, d", Usage: "enable debug log"},
	}

	app.Before = func(c *cli.Context) error {
		if c.GlobalBool("debug") {
			log.SetLevel(log.DebugLevel)
		}

		if log.GetLevel() != log.DebugLevel {
			gin.SetMode(gin.ReleaseMode)
		}

		return nil
	}

	app.ExitErrHandler = func(c *cli.Context, err error) {
		if err != nil {
			log.Error(err)
		}
	}

	app.Commands = append(app.Commands, cli.Command{
		Name: "api",
		Flags: []cli.Flag{
			cli.IntFlag{Name: "port, p", Value: 8888},
			cli.StringFlag{Name: "service_host, s", Value: "http://localhost:8081"},
		},
		Action: func(c *cli.Context) error {
			r := gin.New()
			r.Use(gin.Recovery())
			config := cors.DefaultConfig()
			config.AllowAllOrigins = true
			config.AllowCredentials = true
			config.AddAllowHeaders("Fox-Merchant-Id", "fox-cloud-merchant-id", "Authorization")
			r.Use(cors.New(config))
			r.Use(ginrus.Ginrus(log.StandardLogger(), time.RFC3339, true))

			r.GET("/_hc", func(c *gin.Context) {
				c.AbortWithStatusJSON(http.StatusOK, map[string]interface{}{})
			})

			imp := gatewayImp{
				gatewayHost: "https://dev-gateway.fox.one",
				serviceHost: c.String("service_host"),
			}
			r.Any("/p/:service/*any", imp.public)
			r.Any("/member/:service/p/*any", imp.public)
			r.Any("/member/:service/u/*any", imp.loginRequired(false))
			r.Any("/member/:service/pin/*any", imp.loginRequired(true))
			r.Any("/admin/:service/u/*any", imp.admin)

			addr := fmt.Sprintf(":%d", c.Int("port"))
			return r.Run(addr)
		},
	})

	app.Run(os.Args)
}
