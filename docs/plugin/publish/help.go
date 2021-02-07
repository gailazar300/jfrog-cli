package publish

const Description = "Publish a JFrog CLI plugin."

var Usage = []string{"jfrog plugin publish <plugin name and version> [command options]"}

const Arguments string = `	plugin name and version
		Specifies the name and version of the JFrog CLI Plugin you wish to publish.
		The version should be specified after a '@' separator, such as: 'hello-frog@1.0.0'.`
