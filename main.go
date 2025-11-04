package main

import (
	"context"
	"log"
	"os"

	"github.com/urfave/cli/v3"
	"github.com/anchorageoss/visualsign-turnkeyclient/cmd"
)

func main() {
	app := &cli.Command{
		Name:  "turnkey-client",
		Usage: "Turnkey Visualsign Client",
		Commands: []*cli.Command{
			cmd.ParseCommand(),
			cmd.VerifyCommand(),
			cmd.DecodeCommand(),
			cmd.AttestationCommand(),
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
