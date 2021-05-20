package main

import (
	"fmt"
	"log"
	"os"

	"github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/common"
	"github.com/urfave/cli/v2"
)

func parseArguments() {

	serverString := ""
	username := ""
	keyfile := "keypair.bin"

	period := 5 // seconds

	app := &cli.App{
		Name:    "PV204 Noise TPM chat client",
		Version: "v0.0.1",
	}
	app.UseShortOptionHandling = true
	app.EnableBashCompletion = true
	app.Commands = []*cli.Command{
		{
			Name:  "registration",
			Usage: "Perform a registration",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "server-string", Aliases: []string{"s"}, Required: true},
				&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Required: true},
				&cli.StringFlag{Name: "keyfile", Aliases: []string{"k"}, Value: keyfile},
				&cli.StringFlag{Name: "tpm-path", Aliases: []string{"t"}, Value: common.TPM_PATH},
			},
			Action: func(c *cli.Context) error {
				serverString = c.String("server-string")
				username = c.String("username")
				keyfile = c.String("keyfile")
				common.TPM_PATH = c.String("tpm-path")

				fmt.Println("server-string:", serverString)
				fmt.Println("username:", username)
				fmt.Println("keyfile:", keyfile)
				fmt.Println("tpm-path:", common.TPM_PATH)

				registerSafe(serverString, username, keyfile)
				return nil
			},
		},
		{
			Name:  "login",
			Usage: "Login and do some action. If send-msg or receive-msg are specified the action(s) will be performed and exited. If they are not specified, interactive interface will be launched.",
			Flags: []cli.Flag{
				&cli.IntFlag{Name: "period", Aliases: []string{"p"}, Value: period, Usage: "Value is in seconds"},
				&cli.StringFlag{Name: "keyfile", Aliases: []string{"k"}, Value: keyfile},
				&cli.StringFlag{Name: "tpm-path", Aliases: []string{"t"}, Value: common.TPM_PATH},

				&cli.StringFlag{Name: "send-msg", Aliases: []string{"m"}, Usage: "Non-interactive mode: A single msg to be sent."},
				&cli.BoolFlag{Name: "receive-msg", Aliases: []string{"r"}, Usage: "Non-interactive mode: Using this flag you can retrieve msgs once."},
			},
			Action: func(c *cli.Context) error {

				period = c.Int("period")
				keyfile = c.String("keyfile")
				common.TPM_PATH = c.String("tpm-path")

				fmt.Println("period:", period)
				fmt.Println("keyfile:", keyfile)
				fmt.Println("tpm-path:", common.TPM_PATH)

				login(keyfile)

				start_interactive_mode := true

				msg := c.String("send-msg")
				if len(msg) > 0 {
					// todo: Would we also want to allow empty msg? I don't think so...
					sendMessage(msg)
					start_interactive_mode = false
				}

				if c.Bool("receive-msg") {
					receiveMessages()
					start_interactive_mode = false
				}

				if start_interactive_mode {
					interactiveMode(period)
				}
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	parseArguments()
}
