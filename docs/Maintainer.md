# How to Package Termshark for Release

## Termux (Android)

I've been building use the termux docker builder.

```bash
docker pull termux/package-builder
```

Clone the `termux-packages` and `termux-root-packages` repos:

```bash
cd source/
git clone https://github.com/termux/termux-packages
cd termux-packages
git clone https://github.com/termux/termux-root-packages
```

Open `termux-packages/termux-root-packages/packages/termshark/build.sh` in an editor. Change

```bash
cd $TERMUX_PKG_BUILDDIR
go get -d -v github.com/gcla/termshark/v2/cmd/termshark@e185fa59d87c06fe1bafb83ce6dc15591434ccc8
go install github.com/gcla/termshark/v2/cmd/termshark
```

to use the correct uuid - I am using the uuid for v2.0.3

```bash
cd $TERMUX_PKG_BUILDDIR
go get -d -v github.com/gcla/termshark/v2/cmd/termshark@73dfd1f6cb8c553eb524ebc27d991f637c1ac5ea
go install github.com/gcla/termshark/v2/cmd/termshark
```

Change `TERMUX_PKG_VERSION` too.

Save. Start docker and build (from `termux-packages` dir):

```bash
gcla@elgin:~/source/termux-packages$ ./scripts/run-docker.sh 
Running container 'termux-package-builder' from image 'termux/package-builder'...
builder@201c39983bf8:~/termux-packages$ rm /data/data/.built-packages/termshark
builder@201c39983bf8:~/termux-packages$ ./clean.sh # to rebuild everything!
builder@201c39983bf8:~/termux-packages$ ./build-package.sh termux-root-packages/packages/termshark/
...
```

This will take several minutes. You'll probably see an error like this:

```
Wrong checksum for https://termshark.io:
Expected: 36e45dfeb97f89379bda5be6bfe69c46e5c4211674120977e7b0033f5d90321a
Actual:   c05a64f1e502d406cc149c6e8b92720ad6310aecd1dd206e05713fd8a2247a84
```

Open `termux-packages/termux-root-packages/packages/termshark/build.sh` again and change `TERMUX_PKG_SHA256`. Rebuild.

Submit a PR to `termux-root-packages`.

To edit files in use by a docker container, you can use tramp + emacs with a path like this: `/docker:builder@201c39983bf8:/home/builder/termux-packages/termux-root-packages/packages/termshark/build.sh`

## Snapcraft

Fork Mario's termshark-snap repository: https://github.com/mharjac/termshark-snap (@mharjac) and clone it to a recentish Linux. Edit `snapcraft.yaml`. Change `version:` and edit this section to use the correct hash - this one corresponds to v2.0.3:

```
go get github.com/gcla/termshark/v2/cmd/termshark@73dfd1f6cb8c553eb524ebc27d991f637c1ac5ea
```

From a shell, type

```
snapcraft
```

If you have prior snapcraft builds of termshark, you might need

```
snapcraft clean
```

first. On my 19.10 machine, I ran into snapcraft failures that resolved when I simply ran `snapcraft` again...

When this succeeds, the working directory should have a file `termshark_2.0.3_amd64.snap`. To install this - to test it out - try this:

```
snap install --dangerous ./termshark_2.0.3_amd64.snap
```

then to run it:

```
/snap/bin/termshark -h
```

Check your changes in and submit a PR to Mario (@mharjac).


