module github.com/gcla/termshark

require (
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/antchfx/xmlquery v1.0.0
	github.com/antchfx/xpath v1.0.0 // indirect
	github.com/blang/semver v3.5.1+incompatible
	github.com/gcla/deep v1.0.2
	github.com/gcla/gowid v1.0.1-0.20191103220125-26d856e441b7
	github.com/gdamore/tcell v1.2.1-0.20190805162843-ae1dc54d2c70
	github.com/go-test/deep v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.3
	github.com/hpcloud/tail v1.0.0
	github.com/jessevdk/go-flags v1.4.0
	github.com/mattn/go-isatty v0.0.9
	github.com/mreiferson/go-snappystream v0.2.3
	github.com/pkg/errors v0.8.1
	github.com/pkg/term v0.0.0-20190109203006-aa71e9d9e942
	github.com/shibukawa/configdir v0.0.0-20170330084843-e180dbdc8da0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/viper v1.3.2
	github.com/stretchr/testify v1.3.0
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859 // indirect
	golang.org/x/sys v0.0.0-20191010194322-b09406accb47
	gopkg.in/fsnotify.v1 v1.4.7
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
)

replace github.com/hpcloud/tail => github.com/gcla/tail v1.0.1-0.20191105001453-2a7e4c24a6b5

replace github.com/gdamore/tcell => github.com/gcla/tcell v1.1.2-0.20190930013645-5e4b40606ce2

replace github.com/pkg/term => github.com/gcla/term v0.0.0-20191015020247-31cba2f9f402
