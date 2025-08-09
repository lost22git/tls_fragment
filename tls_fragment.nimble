# Package

version = "0.1.0"
author = "lost"
description = "A new awesome nimble package"
license = "MIT"
srcDir = "src"
bin = @["tls_fragment"]

# Dependencies

requires "nim >= 2.2.4"

requires "weave >= 0.4.10"

task buildSync, "build sync version":
  exec "nimble build --verbose -d:release -d:lto"

task buildAsync, "build async version":
  exec "nimble build --verbose -d:release -d:lto -d:async"

task buildPool, "build thread pool version":
  exec "nimble build --verbose -d:release -d:lto -d:pool"
