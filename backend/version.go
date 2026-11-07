package main

// version is set at build time: -ldflags "-X main.version=…" (scripts/build-deb.sh
// uses scripts/version.sh). Development builds report "dev".
var version = "dev"
