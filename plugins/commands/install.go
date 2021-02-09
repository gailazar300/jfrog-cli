package commands

import (
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-core/utils/config"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/codegangsta/cli"
	"github.com/jfrog/jfrog-cli-core/utils/coreutils"
	pluginsutils "github.com/jfrog/jfrog-cli/plugins/utils"
	"github.com/jfrog/jfrog-cli/utils/cliutils"
	logUtils "github.com/jfrog/jfrog-cli/utils/log"
	"github.com/jfrog/jfrog-cli/utils/progressbar"
	"github.com/jfrog/jfrog-client-go/http/httpclient"
	"github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const pluginsRegistryUrl = "https://releases.jfrog.io/artifactory"
const pluginsRegistryRepo = "jfrog-cli-plugins"
const latestVersionName = "latest"

func InstallCmd(c *cli.Context) error {
	if c.NArg() != 1 {
		return cliutils.PrintHelpAndReturnError("Wrong number of arguments.", c)
	}
	rtDetails, _ := config.GetDefaultArtifactoryConf()
	clientDetails := NewHttpClientDetailsFromArtifactoryDetails(rtDetails)
	fmt.Println(clientDetails)
	return runInstallCmd(c.Args().Get(0), clientDetails)
}

func runInstallCmd(requestedPlugin string, clientDetails *httputils.HttpClientDetails) error {
	pluginName, version, err := getNameAndVersion(requestedPlugin)
	if err != nil {
		return err
	}
	srcPath, err := buildSrcPath(pluginName, version)
	if err != nil {
		return err
	}
	downloadUrl := utils.AddTrailingSlashIfNeeded(coreutils.GetPluginServer()) + srcPath

	pluginsDir, err := coreutils.GetJfrogPluginsDir()
	if err != nil {
		return err
	}

	exists, err := fileutils.IsDirExists(pluginsDir, false)
	if err != nil {
		return err
	}
	if exists {
		should, err := shouldDownloadPlugin(pluginsDir, pluginName, downloadUrl, clientDetails)
		if err != nil {
			return err
		}
		if !should {
			return errors.New("requested plugin already exists locally")
		}
	} else {
		err = createPluginsDir(pluginsDir)
		if err != nil {
			return err
		}
	}

	return downloadPlugin(pluginsDir, pluginName, downloadUrl, clientDetails)
}
func NewHttpClientDetailsFromArtifactoryDetails(rtDetails *config.ArtifactoryDetails) *httputils.HttpClientDetails {
	headers := make(map[string]string)
	return &httputils.HttpClientDetails{
		User:        rtDetails.User,
		Password:    rtDetails.Password,
		ApiKey:      rtDetails.ApiKey,
		AccessToken: rtDetails.AccessToken,
		Headers:     headers}
}
func shouldDownloadPlugin(pluginsDir, pluginName, downloadUrl string, clientDetails *httputils.HttpClientDetails) (bool, error) {
	log.Debug("Verifying plugin download is needed...")
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		return false, err
	}
	log.Debug("Fetching plugin details from: ", downloadUrl)

	details, resp, err := client.GetRemoteFileDetails(downloadUrl, *clientDetails)
	if err != nil {
		return false, err
	}
	log.Debug("Artifactory response: ", resp.Status)
	err = errorutils.CheckResponseStatus(resp, http.StatusOK)
	if err != nil {
		return false, err
	}
	isEqual, err := fileutils.IsEqualToLocalFile(filepath.Join(pluginsDir, pluginName), details.Checksum.Md5, details.Checksum.Sha1)
	return !isEqual, err
}

func buildSrcPath(pluginName, version string) (string, error) {
	arc, err := getArchitecture()
	if err != nil {
		return "", err
	}
	return path.Join(pluginsRegistryRepo, pluginName, version, arc, pluginsutils.GetPluginExecutableName(pluginName)), nil
}

func createPluginsDir(pluginsDir string) error {
	return os.MkdirAll(pluginsDir, 0777)
}

func downloadPlugin(pluginsDir, pluginName, downloadUrl string, clientDetails *httputils.HttpClientDetails) error {
	exeName := pluginsutils.GetPluginExecutableName(pluginName)
	log.Debug("Downloading plugin from: ", downloadUrl)
	downloadDetails := &httpclient.DownloadFileDetails{
		FileName:      pluginName,
		DownloadPath:  downloadUrl,
		LocalPath:     pluginsDir,
		LocalFileName: exeName,
		RelativePath:  exeName,
	}

	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		return err
	}
	// Init progress bar.
	progressMgr, logFile, err := progressbar.InitProgressBarIfPossible()
	if err != nil {
		return err
	}
	if progressMgr != nil {
		progressMgr.IncGeneralProgressTotalBy(1)
		defer logUtils.CloseLogFile(logFile)
		defer progressMgr.Quit()
	}
	log.Info("Downloading plugin: " + pluginName)
	resp, err := client.DownloadFileWithProgress(downloadDetails, "", *clientDetails, 3, false, progressMgr)
	if err != nil {
		return err
	}
	log.Debug("Artifactory response: ", resp.Status)
	err = errorutils.CheckResponseStatus(resp, http.StatusOK)
	if err != nil {
		return err
	}
	log.Debug("Plugin downloaded successfully.")
	return os.Chmod(filepath.Join(pluginsDir, exeName), 0777)
}
func createArtifactoryDetailsFromOptions(c *cli.Context) (details *config.ArtifactoryDetails) {
	details = new(config.ArtifactoryDetails)
	details.Url = c.String("url")
	details.DistributionUrl = c.String("dist-url")
	details.ApiKey = c.String("apikey")
	details.User = c.String("user")
	details.Password = c.String("password")
	details.SshKeyPath = c.String("ssh-key-path")
	details.SshPassphrase = c.String("ssh-passphrase")
	details.AccessToken = c.String("access-token")
	details.ClientCertPath = c.String("client-cert-path")
	details.ClientCertKeyPath = c.String("client-cert-key-path")
	details.ServerId = c.String("server-id")
	details.InsecureTls = c.Bool("insecure-tls")
	if details.ApiKey != "" && details.User != "" && details.Password == "" {
		// The API Key is deprecated, use password option instead.
		details.Password = details.ApiKey
		details.ApiKey = ""
	}
	details.Url = utils.AddTrailingSlashIfNeeded(details.Url)
	details.DistributionUrl = utils.AddTrailingSlashIfNeeded(details.DistributionUrl)
	return
}

func getNameAndVersion(requested string) (name, version string, err error) {
	split := strings.Split(requested, "@")
	if len(split) == 1 || (len(split) == 2 && split[1] == "") {
		return split[0], latestVersionName, nil
	}
	if len(split) > 2 {
		return "", "", errors.New("unexpected number of '@' separators in provided argument")
	}
	return split[0], split[1], nil
}

// Get the architecture name corresponding to the architectures that exist in registry.
func getArchitecture() (string, error) {
	switch runtime.GOOS {
	case "windows":
		return "windows-amd64", nil
	case "darwin":
		return "mac-386", nil
	}
	// Assuming linux.
	switch runtime.GOARCH {
	case "amd64":
		return "linux-amd64", nil
	case "arm64":
		return "linux-arm64", nil
	case "arm":
		return "linux-arm", nil
	case "386":
		return "linux-386", nil
	case "s390x":
		return "linux-s390x", nil
	}
	return "", errors.New("no compatible plugin architecture was found for the architecture of this machine")
}
