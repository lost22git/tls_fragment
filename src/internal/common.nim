import std/[strformat, net, logging, exitprocs, random, strutils]

func be16*(data: openArray[char]): uint16 =
  ## big endian decode

  doAssert data.len == 2
  (data[0].uint16 shl 8) + (data[1].uint16)

func be16*(value: int): string =
  ## big endian encode

  result.add ((value shr 8) and 0xff).char
  result.add ((value shr 0) and 0xff).char

func be32*(data: openArray[char]): uint32 =
  ## big endian decode

  doAssert data.len <= 4
  for i in (0 .. data.high):
    result += (data[data.high - i].uint32 shl (i * 8))

converter hostPortConvert*(v: (string, Port)): (string, uint16) =
  let (host, port) = v
  return (host, port.uint16)

func `$`*(v: (string, uint16)): string =
  fmt"{v[0]}:{v[1]}"

func `$`*(v: (string, Port)): string =
  fmt"{v[0]}:{v[1]}"

func add*(s: var string, data: openArray[char]) =
  for c in data:
    s.add c

proc randomSlice*(init: Slice[int], minLen = 1): seq[Slice[int]] =
  ## random slice
  ## randomly divide a large slice into several smaller slices

  doAssert init.a <= init.b
  doAssert minLen > 0

  let maxCount = (init.len div minLen) + 1

  var rand = initRand()

  var r = init
  var c = 0
  while c < maxCount - 1 and r.len > minLen:
    if (let v = r.a .. rand.rand(r); v.len >= minLen):
      result.add v
      inc c
      r.a = v.b + 1

  if r.len > 0:
    result.add r

type ProxyProtocol* = enum
  Unknown
  None
  Http
  Socks5

# === TLS client hello ===

proc extractSniFromExtension*(data: openArray[char]): string =
  ## extract sni from the content of server_name extension

  if data[2].int == 0: # server name list entry type is 'DNS host name'
    let sniLen = data[3 .. 4].be32.int
    assert (5 + sniLen) <= data.len
    return data[5 ..< (5 + sniLen)].join

proc parseTlsClientHello*(data: openArray[char]): (string, bool) =
  ## return tuple (sni and isTls13)
  ## if key_share extension exists then isTls13 is true

  var pos = 0
  let
    clientVersionLen = 2
    clientRandomLen = 32
  pos += clientVersionLen + clientRandomLen
  if data.len <= pos:
    raise newException(
      ValueError, "invalid TLS client hello message, too small (session id)"
    )
  let sessionIdLen = data[pos].int
  pos += 1 + sessionIdLen
  if data.len <= pos + 1:
    raise newException(
      ValueError, "invalid TLS client hello message, too small (cipher suites)"
    )
  let cipherSuitesLen = data[pos .. (pos + 1)].be32.int
  pos += 2 + cipherSuitesLen
  if data.len <= pos:
    raise newException(
      ValueError, "invalid TLS client hello message, too small (compression methods)"
    )
  let compressionMethodsLen = data[pos].int
  pos += 1 + compressionMethodsLen
  if data.len <= pos + 1:
    raise newException(
      ValueError, "invalid TLS client hello message, too small (extensions)"
    )
  let extensionsLen = data[pos .. (pos + 1)].be32.int
  pos += 2
  if data.len != pos + extensionsLen:
    raise
      newException(ValueError, "invalid TLS client hello message, inconsistent length")

  while pos < data.len:
    let eid = data[pos .. (pos + 1)].be32.int
    pos += 2
    let elen = data[pos .. (pos + 1)].be32.int
    pos += 2
    case eid
    # server_name
    of 0x00:
      result[0] = extractSniFromExtension(data[pos ..< (pos + elen)])
    # key_share
    of 0x33:
      result[1] = true
    else:
      discard
    pos += elen

proc fragmentizeTlsClientHello*(
    data: string, sni: string, recordHeader: openArray[char]
): seq[string] =
  ## fragmentize TLS client hello message to avoid exposing SNI

  let l = data.find(sni)
  let r = l + sni.len - 1

  var tcpData = ""

  # tls fragmentize
  for range in randomSlice(0 ..< l, minLen = 8):
    tcpData.add recordHeader
    tcpData.add range.len.be16
    tcpData.add data[range]
  for range in randomSlice(l .. r, minLen = 4):
    tcpData.add recordHeader
    tcpData.add range.len.be16
    tcpData.add data[range]
  for range in randomSlice((r + 1) .. data.high, minLen = 8):
    tcpData.add recordHeader
    tcpData.add range.len.be16
    tcpData.add data[range]

  # tcp fragmentize
  for range in randomSlice(0 .. tcpData.high, 4):
    result.add tcpData[range]

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
  newConsoleLogger(fmtStr = "$levelId$datetime| ", levelThreshold = config.logLevel)

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
