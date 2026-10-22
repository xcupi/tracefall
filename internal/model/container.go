package model

// Container and Grafana evidence. A container's own files (its JSON log, its
// config and host config) describe what the container engine recorded about it.
// They are not a view inside the container: a process that ran in the container
// but wrote nowhere the engine captured is invisible here.
const (
	ArtifactContainerLog    = "container_json_log"
	ArtifactContainerConfig = "container_config"
	ArtifactGrafanaLog      = "grafana_log"
	ArtifactGrafanaDB       = "grafana_database"

	// EventContainerLog is one line a container wrote to stdout or stderr, with
	// the engine's own timestamp for when it received the line.
	EventContainerLog = "container_log"
	// EventContainerConfig is a container's recorded configuration and state:
	// image, command, environment variable NAMES, published ports, mounts.
	EventContainerConfig = "container_config"
	// EventContainerHostConfig is the privileges and isolation settings a
	// container was started with.
	EventContainerHostConfig = "container_host_config"

	// EventGrafanaLog is a Grafana application log line that is not a request.
	EventGrafanaLog = "grafana_log"
	// Records read from grafana.db. They are what Grafana stored, not proof of
	// who caused it.
	EventGrafanaUser         = "grafana_user"
	EventGrafanaToken        = "grafana_token"
	EventGrafanaDataSource   = "grafana_datasource"
	EventGrafanaLoginAttempt = "grafana_login_attempt"
	EventGrafanaSession      = "grafana_session"
)
