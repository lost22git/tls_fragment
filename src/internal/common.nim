import std/[strformat, net, logging, exitprocs]

func bigEndian16*(data: openArray[char]): uint16 =
  (data[0].uint16 shl 8) + (data[1].uint16)

converter hostPortConvert*(v: (string, Port)): (string, uint16) =
  let (host, port) = v
  return (host, port.uint16)

func `$`*(v: (string, uint16)): string =
  fmt"{v[0]}:{v[1]}"

func `$`*(v: (string, Port)): string =
  fmt"{v[0]}:{v[1]}"

type ProxyProtocol* = enum
  Unknown
  Http
  Socks5

# === Config ===

type ServerConfig* = object
  host*: string = "127.0.0.1"
  port*: uint16 = 9933
  backlog*: int32 = 128

type ClientConfig* = object
  cnnTimeout* = 3000

type Config* = object
  server*: ServerConfig
  client*: ClientConfig
  logLevel*: Level = lvlAll

when defined(release):
  let config* = Config(logLevel: lvlInfo)
else:
  let config* = Config()

# === Logging ===

let logger* =
  newConsoleLogger(fmtStr = "$levelId$datetime - ", levelThreshold = config.logLevel)

addHandler(logger)

# === Exit Hook ===

setControlCHook(
  proc() {.noconv.} =
    echo "CTRL-C was pressed"
    quit()
)
addExitProc(
  proc() =
    echo "program is exiting"
)
