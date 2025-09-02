# Package

version = "0.1.0"
author = "lost"
description = "A new awesome nimble package"
license = "MIT"
srcDir = "src"
bin = @["tls_fragment"]
binDir = "bin"

# Dependencies

requires "nim >= 2.2.4"

requires "weave >= 0.4.10"

requires "chronicles >= 0.12.1"

requires "threading >= 0.2.1"

task buildSync, "build sync version":
  exec "nimble build --verbose -d:release -d:lto --mm:atomicArc"

task buildPool, "build thread pool version":
  exec "nimble build --verbose -d:release -d:lto --mm:atomicArc -d:pool"

task buildAsync, "build async version":
  exec "nimble build --verbose -d:release -d:lto --threads:off -d:useMalloc -d:async"

task printProcessInfo, "print process info":
  exec "ps Hu $(pgrep tls_fragment)"
