/*
   Copyright The containerd Authors.

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

package main

import (
	"fmt"
	"os"

	"github.com/containerd/containerd/cmd/ctr/app"
	"github.com/containerd/containerd/pkg/seed"
	"github.com/dragonflyoss/image-service/contrib/ctr-remote/commands"
	"github.com/urfave/cli"
)

func init() {
	seed.WithTimeAndRand()
}

func main() {
	customCommands := []cli.Command{commands.RpullCommand}
	app := app.New()
	for i := range app.Commands {
		if app.Commands[i].Name == "images" {
			sc := map[string]cli.Command{}
			for _, subcmd := range customCommands {
				sc[subcmd.Name] = subcmd
			}

			// First, replace duplicated subcommands
			for j := range app.Commands[i].Subcommands {
				for name, subcmd := range sc {
					if name == app.Commands[i].Subcommands[j].Name {
						app.Commands[i].Subcommands[j] = subcmd
						delete(sc, name)
					}
				}
			}

			// Next, append all new sub commands
			for _, subcmd := range sc {
				app.Commands[i].Subcommands = append(app.Commands[i].Subcommands, subcmd)
			}
			break
		}
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "ctr: %v\n", err)
		os.Exit(1)
	}
}
