package main

import (
	"github.com/jfrog/jfrog-cli-core/utils/coreutils"
	"github.com/jfrog/jfrog-cli/utils/tests"
	"github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

// JFrog CLI for Xray commands
var xrayCli *tests.JfrogCli

func initXrayTest(t *testing.T) {
	if !*tests.TestXray {
		t.Skip("Skipping artifactory test. To run artifactory test add the '-test.artifactory=true' option.")
	}
}

func InitXrayTests() {
	initXrayCli()
	////	tests.AddTimestampToGlobalVars()
}

func CleanXrayTests() {

}

func cleanXrayTest() {
	if !*tests.TestXray {
		return
	}
	os.Unsetenv(coreutils.HomeDir)
	log.Info("Cleaning test data...")
	tests.CleanFileSystem()
}

func initXrayCli() {
	if xrayCli != nil {
		return
	}
	*tests.XrUrl = utils.AddTrailingSlashIfNeeded(*tests.XrUrl)
	xrayCli = tests.NewJfrogCli(execMain, "jfrog xr", authenticate(true))
	if *tests.TestXray {
		configCli = createConfigJfrogCLI(authenticate(true))
	}
}

func createServerConfig() (err error) {
	deleteXrServerConfig()
	return configCli.Exec("add", tests.XrServerId)
}

func deleteXrServerConfig() {
	configCli.WithoutCredentials().Exec("rm", tests.XrServerId, "--quiet")
}

func TestXrayCurl(t *testing.T) {
	initXrayTest(t)
	xrayCommandExecutor := tests.NewJfrogCli(execMain, "jfrog xr", "")
	//Check curl command with config default server
	err := xrayCommandExecutor.Exec("curl", "-XGET", "/api/v1/system/version")
	assert.NoError(t, err)
	//Check curl command with '--server-id' flag
	err = createServerConfig()
	defer deleteXrServerConfig()
	assert.NoError(t, err)
	err = xrayCommandExecutor.Exec("curl", "-XGET", "/api/v1/system/version", "--server-id="+tests.XrServerId)
	assert.NoError(t, err)
	// Check curl command with invalid server id - should get an error.
	err = xrayCommandExecutor.Exec("curl", "-XGET", "/api/v1/system/version", "--server-id=invalid_name"+tests.XrServerId)
	assert.Error(t, err)

	cleanXrayTest()
}
