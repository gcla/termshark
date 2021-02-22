module github.com/gcla/termshark/v2

go 1.13

require (
	github.com/adam-hanna/arrayOperations v0.2.6
	github.com/antchfx/xmlquery v1.3.3
	github.com/antchfx/xpath v1.1.11 // indirect
	github.com/blang/semver v3.5.1+incompatible
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/gcla/deep v1.0.2
	github.com/gcla/gowid v1.2.1-0.20210222002349-f33d36dc358a
	github.com/gcla/tail v1.0.1-0.20190505190527-650e90873359
	github.com/gdamore/tcell v1.3.1-0.20200115030318-bff4943f9a29
	github.com/go-test/deep v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4
	github.com/jessevdk/go-flags v1.4.0
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/mattn/go-isatty v0.0.12
	github.com/mitchellh/go-homedir v1.0.0
	github.com/mitchellh/mapstructure v1.4.0 // indirect
	github.com/mreiferson/go-snappystream v0.2.3
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/pkg/errors v0.9.1
	github.com/pkg/term v1.1.0
	github.com/rakyll/statik v0.1.7
	github.com/shibukawa/configdir v0.0.0-20170330084843-e180dbdc8da0
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/afero v1.5.1 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	github.com/tevino/abool v1.2.0
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b // indirect
	golang.org/x/sys v0.0.0-20210108172913-0df2131ae363 // indirect
	golang.org/x/text v0.3.5 // indirect
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7
	gopkg.in/ini.v1 v1.62.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace github.com/gdamore/tcell => github.com/gcla/tcell v1.1.2-0.20200927150251-decc2045f510

replace github.com/pkg/term => github.com/gcla/term v0.0.0-20191015020247-31cba2f9f402
