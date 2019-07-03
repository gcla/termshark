module github.com/gcla/termshark

require (
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/blang/semver v3.5.1+incompatible
	github.com/gcla/deep v1.0.2
	github.com/gcla/gowid v1.0.1-0.20190701141247-30d8e3104c2a
	github.com/gdamore/tcell v1.1.3-0.20190613063818-ca8fb5bcc94b
	github.com/hashicorp/golang-lru v0.5.1
	github.com/jessevdk/go-flags v1.4.0
	github.com/mattn/go-isatty v0.0.7
	github.com/pkg/errors v0.8.1
	github.com/shibukawa/configdir v0.0.0-20170330084843-e180dbdc8da0
	github.com/sirupsen/logrus v1.4.1
	github.com/spf13/viper v1.3.2
	github.com/stretchr/testify v1.3.0
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7
)

replace github.com/gdamore/tcell => github.com/gcla/tcell v1.1.2-0.20190617025252-1097a48ec082
