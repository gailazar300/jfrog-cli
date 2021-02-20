package commands

import (
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-core/artifactory/commands"
	"github.com/jfrog/jfrog-cli-core/artifactory/commands/generic"
	"github.com/jfrog/jfrog-cli-core/artifactory/spec"
	artifactoryUtils "github.com/jfrog/jfrog-cli-core/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/utils/config"
	"github.com/jfrog/jfrog-cli-core/utils/ioutils"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
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
	return runInstallCmd(c.Args().Get(0), c)
}

func runInstallCmd(requestedPlugin string, c *cli.Context) error {
	pluginServer, installPrivate := getPluginServer()
	pluginName, version, err := getNameAndVersion(requestedPlugin)
	if err != nil {
		return err
	}
	srcPath, err := buildSrcPath(pluginName, version)
	if err != nil {
		return err
	}
	downloadUrl := utils.AddTrailingSlashIfNeeded(pluginServer) + srcPath

	pluginsDir, err := coreutils.GetJfrogPluginsDir()
	if err != nil {
		return err
	}

	exists, err := fileutils.IsDirExists(pluginsDir, false)
	if err != nil {
		return err
	}
	if !exists {
		err = createPluginsDir(pluginsDir)
		if err != nil {
			return err
		}
	}
	should, err := shouldDownloadPlugin(pluginsDir, pluginName, srcPath, downloadUrl, installPrivate, c)
	if err != nil {
		return err
	}
	if !should {
		return errors.New("requested plugin already exists locally")
	}
	return downloadPlugin(pluginsDir, pluginName, srcPath, downloadUrl, installPrivate, c)
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
func shouldDownloadPlugin(pluginsDir, pluginName, srcPath, downloadUrl string, private bool, c *cli.Context) (bool, error) {
	var checksumMd5, checksumSha1 string
	if private {
		details, err := GetLocalPluginDetails(srcPath, c)
		if err != nil {
			return false, err
		}
		checksumMd5 = details.Md5
		checksumSha1 = details.Sha1
	} else {
		details, err := GetRemotePluginDetails(pluginsDir, pluginName, downloadUrl)
		if err != nil {
			return false, err
		}
		checksumMd5 = details.Checksum.Md5
		checksumSha1 = details.Checksum.Sha1
	}
	isEqual, err := fileutils.IsEqualToLocalFile(filepath.Join(pluginsDir, pluginName), checksumMd5, checksumSha1)
	return !isEqual, err
}

func GetRemotePluginDetails(pluginsDir, pluginName, downloadUrl string) (*fileutils.FileDetails, error) {
	log.Debug("Verifying plugin download is needed...")
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		return nil, err
	}
	log.Debug("Fetching plugin details from: ", downloadUrl)

	details, resp, err := client.GetRemoteFileDetails(downloadUrl, httputils.HttpClientDetails{})
	if err != nil {
		return nil, err
	}
	log.Debug("Artifactory response: ", resp.Status)
	err = errorutils.CheckResponseStatus(resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return details, nil
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

func downloadPublicPlugin(pluginsDir, pluginName, exeName, downloadUrl string, progressMgr ioUtils.ProgressMgr) error {

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
	resp, err := client.DownloadFileWithProgress(downloadDetails, "", httputils.HttpClientDetails{}, 3, false, progressMgr)
	if err != nil {
		return err
	}
	log.Debug("Artifactory response: ", resp.Status)
	err = errorutils.CheckResponseStatus(resp, http.StatusOK)
	if err != nil {
		return err
	}
	log.Debug("Plugin downloaded successfully.")
	return nil
}

func downloadPlugin(pluginsDir, pluginName, srcPath, downloadUrl string, private bool, c *cli.Context) error {
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
	exeName := pluginsutils.GetPluginExecutableName(pluginName)
	if private {
		downloadPrivatePlugin(pluginsDir, srcPath, c, progressMgr)
	} else {
		downloadPublicPlugin(pluginsDir, pluginName, exeName, downloadUrl, progressMgr)
	}
	return os.Chmod(filepath.Join(pluginsDir, exeName), 0777)
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

func getPluginServer() (pluginServer string, envVariable bool) {
	pluginServer = os.Getenv(coreutils.PluginServer)
	if pluginServer == "" {
		return pluginsRegistryUrl, false
	}
	return pluginServer, true
}
func downloadPrivatePlugin(pluginsDir, srcPath string, c *cli.Context, progressMgr ioUtils.ProgressMgr) error {
	rtDetails, err := createArtifactoryDetailsWithConfigOffer(c, false)
	if err != nil {
		return err
	}
	configuration := createDownloadConfiguration()
	downloadSpec, err := createDefaultDownloadSpec(pluginsDir+"/", srcPath, c)
	if err != nil {
		return err
	}
	fixWinPathsForDownloadCmd(downloadSpec)
	buildConfiguration, err := createBuildConfigurationWithModule(c)
	if err != nil {
		return err
	}
	downloadCommand := generic.NewDownloadCommand()
	downloadCommand.SetConfiguration(configuration).SetBuildConfiguration(buildConfiguration).SetSpec(downloadSpec).SetRtDetails(rtDetails)
	downloadCommand.Run()

	result := downloadCommand.Result()
	err = cliutils.PrintSummaryReport(result.SuccessCount(), result.FailCount(), result.Reader(), rtDetails.Url, err)

	return cliutils.GetCliError(err, result.SuccessCount(), result.FailCount(), false)
}
func GetLocalPluginDetails(srcPath string, c *cli.Context) (*artifactoryUtils.SearchResult, error) {
	searchSpec, err := createDefaultSearchSpec(srcPath, c)
	if err != nil {
		return nil, err
	}
	err = spec.ValidateSpec(searchSpec.Files, false, true)
	if err != nil {
		return nil, err
	}
	artDetails, err := createArtifactoryDetailsWithConfigOffer(c, false)
	if err != nil {
		return nil, err
	}
	searchCmd := generic.NewSearchCommand()
	searchCmd.SetRtDetails(artDetails).SetSpec(searchSpec)
	searchCmd.Run()
	reader := searchCmd.Result().Reader()
	searchResult := new(artifactoryUtils.SearchResult)
	err = reader.NextRecord(searchResult)
	if err != nil {
		return nil, err
	}
	return searchResult, nil
}
func createDefaultSearchSpec(srcPath string, c *cli.Context) (*spec.SpecFiles, error) {
	offset, limit := 0, 0
	return spec.NewBuilder().
		Pattern(srcPath).
		Props(c.String("props")).
		ExcludeProps(c.String("exclude-props")).
		Build(c.String("build")).
		ExcludeArtifacts(c.Bool("exclude-artifacts")).
		IncludeDeps(c.Bool("include-deps")).
		Bundle(c.String("bundle")).
		Offset(offset).
		Limit(limit).
		SortOrder(c.String("sort-order")).
		SortBy(cliutils.GetStringsArrFlagValue(c, "sort-by")).
		Recursive(c.BoolT("recursive")).
		ExcludePatterns(cliutils.GetStringsArrFlagValue(c, "exclude-patterns")).
		Exclusions(cliutils.GetStringsArrFlagValue(c, "exclusions")).
		IncludeDirs(c.Bool("include-dirs")).
		ArchiveEntries(c.String("archive-entries")).
		BuildSpec(), nil
}
func createBuildConfigurationWithModule(c *cli.Context) (buildConfigConfiguration *artifactoryUtils.BuildConfiguration, err error) {
	buildConfigConfiguration = new(artifactoryUtils.BuildConfiguration)
	buildConfigConfiguration.BuildName, buildConfigConfiguration.BuildNumber = artifactoryUtils.GetBuildNameAndNumber(c.String("build-name"), c.String("build-number"))
	buildConfigConfiguration.Module = c.String("module")
	err = artifactoryUtils.ValidateBuildAndModuleParams(buildConfigConfiguration)
	return
}

func createArtifactoryDetailsWithConfigOffer(c *cli.Context, excludeRefreshableTokens bool) (*config.ArtifactoryDetails, error) {
	createdDetails, err := offerConfig(c)
	if err != nil {
		return nil, err
	}
	if createdDetails != nil {
		return createdDetails, err
	}

	details := createArtifactoryDetailsFromOptions(c)
	// If urls or credentials were passed as options, use options as they are.
	// For security reasons, we'd like to avoid using part of the connection details from command options and the rest from the config.
	// Either use command options only or config only.
	if credentialsChanged(details) {
		return details, nil
	}

	// Else, use details from config for requested serverId, or for default server if empty.
	confDetails, err := commands.GetConfig(details.ServerId, excludeRefreshableTokens)
	if err != nil {
		return nil, err
	}

	// Take InsecureTls value from options since it is not saved in config.
	confDetails.InsecureTls = details.InsecureTls
	confDetails.Url = utils.AddTrailingSlashIfNeeded(confDetails.Url)
	confDetails.DistributionUrl = utils.AddTrailingSlashIfNeeded(confDetails.DistributionUrl)

	// Create initial access token if needed.
	if !excludeRefreshableTokens {
		err = config.CreateInitialRefreshableTokensIfNeeded(confDetails)
		if err != nil {
			return nil, err
		}
	}

	return confDetails, nil
}
func credentialsChanged(details *config.ArtifactoryDetails) bool {
	return details.Url != "" || details.DistributionUrl != "" || details.User != "" || details.Password != "" ||
		details.ApiKey != "" || details.SshKeyPath != "" || details.SshPassphrase != "" || details.AccessToken != "" ||
		details.ClientCertKeyPath != "" || details.ClientCertPath != ""
}
func fixWinPathsForDownloadCmd(uploadSpec *spec.SpecFiles) {
	if coreutils.IsWindows() {
		for i, file := range uploadSpec.Files {
			uploadSpec.Files[i].Target = fixWinPathBySource(file.Target)
		}
	}
}

func fixWinPathBySource(path string) string {
	if strings.Count(path, "/") > 0 {
		// Assuming forward slashes - not doubling backslash to allow regexp escaping
		return ioutils.UnixToWinPathSeparator(path)
	}
	return path
}

func createDefaultDownloadSpec(pluginsDir, downloadUrl string, c *cli.Context) (*spec.SpecFiles, error) {
	offset, limit := 0, 0
	return spec.NewBuilder().
		Pattern(strings.TrimPrefix(downloadUrl, "/")).
		Props(c.String("props")).
		ExcludeProps(c.String("exclude-props")).
		Build(c.String("build")).
		ExcludeArtifacts(c.Bool("exclude-artifacts")).
		IncludeDeps(c.Bool("include-deps")).
		Bundle(c.String("bundle")).
		Offset(offset).
		Limit(limit).
		SortOrder(c.String("sort-order")).
		SortBy(cliutils.GetStringsArrFlagValue(c, "sort-by")).
		Recursive(c.BoolT("recursive")).
		ExcludePatterns(cliutils.GetStringsArrFlagValue(c, "exclude-patterns")).
		Exclusions(cliutils.GetStringsArrFlagValue(c, "exclusions")).
		Flat(true).
		Explode(c.String("explode")).
		IncludeDirs(c.Bool("include-dirs")).
		Target(pluginsDir).
		ArchiveEntries(c.String("archive-entries")).
		ValidateSymlinks(c.Bool("validate-symlinks")).
		BuildSpec(), nil
}
func createDownloadConfiguration() (downloadConfiguration *artifactoryUtils.DownloadConfiguration) {
	downloadConfiguration = new(artifactoryUtils.DownloadConfiguration)
	downloadConfiguration.MinSplitSize = -1
	downloadConfiguration.SplitCount = 0
	downloadConfiguration.Threads = 1
	downloadConfiguration.Retries = 3
	downloadConfiguration.Symlink = true
	return
}
func offerConfig(c *cli.Context) (*config.ArtifactoryDetails, error) {
	var exists bool
	exists, err := config.IsArtifactoryConfExists()
	if err != nil || exists {
		return nil, err
	}

	var ci bool
	if ci, err = utils.GetBoolEnvValue(coreutils.CI, false); err != nil {
		return nil, err
	}
	var offerConfig bool
	if offerConfig, err = utils.GetBoolEnvValue(cliutils.OfferConfig, !ci); err != nil {
		return nil, err
	}
	if !offerConfig {
		config.SaveArtifactoryConf(make([]*config.ArtifactoryDetails, 0))
		return nil, nil
	}

	msg := fmt.Sprintf("To avoid this message in the future, set the %s environment variable to false.\n"+
		"The CLI commands require the Artifactory URL and authentication details\n"+
		"Configuring JFrog CLI with these parameters now will save you having to include them as command options.\n"+
		"You can also configure these parameters later using the 'jfrog rt c' command.\n"+
		"Configure now?", cliutils.OfferConfig)
	confirmed := coreutils.AskYesNo(msg, false)
	if !confirmed {
		config.SaveArtifactoryConf(make([]*config.ArtifactoryDetails, 0))
		return nil, nil
	}
	details := createArtifactoryDetailsFromOptions(c)
	configCmd := commands.NewConfigCommand().SetDefaultDetails(details).SetInteractive(true).SetEncPassword(true)
	err = configCmd.Config()
	if err != nil {
		return nil, err
	}

	return configCmd.RtDetails()
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
