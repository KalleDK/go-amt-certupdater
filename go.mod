module github.com/KalleDK/go-amt-certupdater

go 1.25.0

require (
	github.com/device-management-toolkit/go-wsman-messages/v2 v2.30.4
	github.com/spf13/cobra v1.10.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/sys v0.18.0 // indirect
)

replace github.com/device-management-toolkit/go-wsman-messages/v2 v2.30.4 => github.com/KalleDK/go-wsman-messages/v2 v2.0.0-20250903121058-8ecefad42c27
