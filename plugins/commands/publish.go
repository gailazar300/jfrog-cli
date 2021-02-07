package commands

import (
	"github.com/codegangsta/cli"
	"github.com/jfrog/jfrog-cli-core/utils/coreutils"
	"github.com/jfrog/jfrog-cli/utils/cliutils"
	"github.com/jfrog/jfrog-client-go/utils"
)

func PublishCmd(c *cli.Context) error {
	if c.NArg() != 1 {
		return cliutils.PrintHelpAndReturnError("Wrong number of arguments.", c)
	}
	return runPublishCmd(c.Args().Get(0))
}

//
func runPublishCmd(newPlugin string) error {
	pluginName, version, err := getNameAndVersion(newPlugin)
	if err != nil {
		return err
	}
	publishUrl := utils.AddTrailingSlashIfNeeded(coreutils.GetPluginServer()) + `/` + coreutils.GetPluginRepository()
}
