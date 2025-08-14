import std/[strformat, strutils, sequtils, net, logging, typedThreads, oids]
import ./common

when defined(pool):
  import weave

when defined(pool):
  echo "=== POOL ==="
else:
  echo "=== SYNC ==="

# === Proxy Protocol Handshake ===

proc guessProxyProtocol(client: Socket): ProxyProtocol =
  ## guess proxy protocol

  var data = client.recv(1)
  if data[0].int == 0x05:
    return Socks5
  if data[0] == 'C':
    data = client.recv(6)
    if data == "ONNECT":
      return Http
  return Unknown

proc socks5ProxyExtractServerAddr(client: Socket): (string, uint16) =
  ## extract remote server address from socks5 proxy handshake

  let addrType = client.recv(1)[0].int
  case addrType
  of 0x01: # IPV4
    var data: array[0 .. 3, uint8]
    discard client.recv(data.addr, 4)
    let ipv4 = IpAddress(family: IPv4, address_v4: data)
    let port = client.recv(2).be16()
    result = ($ipv4, port)
  of 0x03: # Domain name (len(1B)+name)
    let len = client.recv(1)[0].int
    let domain = client.recv(len)
    let port = client.recv(2).be16()
    result = (domain, port)
  of 0x04: # IPV6
    var data: array[0 .. 15, uint8]
    discard client.recv(data.addr, 16)
    let ipv6 = IpAddress(family: IPv6, address_v6: data)
    let port = client.recv(2).be16()
    result = ($ipv6, port)
  else:
    return

proc socks5ProxyHandshake(client: Socket): (string, uint16) =
  ## handle socks5 proxy handshake
  ##
  ## https://en.m.wikipedia.org/wiki/SOCKS
  ##
  ## NOTE:
  ## we only support tcp and no auth now.

  let clientAddr = client.getPeerAddr()

  # 1. initial request
  let nauth = client.recv(1)[0].int
  discard client.recv(nauth)
  client.send("\x05\x00") # no auth
  info clientAddr, ": ", fmt"socks5 proxy handshake: auth=0x00(no auth)"

  # 2. auth requeset (skip when no auth)

  # 3. client connection request
  let header = client.recv(3)
  # echo fmt"{header.repr =}"
  assert header[0].int == 0x05
  let cmd = header[1].int
  case cmd
  of 0x01: # establish a TCP/IP stream connection
    let serverAddr = socks5ExtractServerAddr(client)
    if serverAddr == default((string, uint16)):
      client.send("\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
      raise newException(
        ValueError, "socks5 proxy handshake error: address type not supported"
      )
    else:
      info clientAddr, ": ", fmt"socks5 proxy handshake: {serverAddr=}"
      client.send("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
      return serverAddr
  else:
    client.send("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
    raise newException(
      ValueError,
      fmt"socks5 proxy handshake error: command({cmd}) not supported / protocol error",
    )

proc httpProxyExtractServerAddr(client: Socket): (string, uint16) =
  ## extract remote server address from http proxy handshake
  ##
  ## NOTE:
  ## we find remote server address from `Host` header,
  ## and not authentication support now.

  var line = ""
  while true:
    client.readLine(line)
    if line == "\r\n":
      return
    if line.startsWith("Host: "):
      let split = line[6 ..^ 1].split(":")
      result = (split[0], split[1].parseInt().uint16)

proc httpProxyHandshake(client: Socket): (string, uint16) =
  ## handle http proxy handshake

  let clientAddr = client.getPeerAddr()
  let serverAddr = httpProxyExtractServerAddr(client)
  if serverAddr == default((string, uint16)):
    client.send("HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n")
    raise newException(ValueError, "http proxy handshake error: serverAddr not found")
  info clientAddr, ": ", fmt"http proxy handshake: {serverAddr=}"
  client.send("HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n")
  return serverAddr

proc proxyHandshake(client: Socket): (string, uint16) =
  ## handle proxy handshake
  ##
  ## supported proxy protocols:
  ## 1. http
  ## 2. socks5

  case guessProxyProtocol(client)
  of Http:
    result = httpProxyHandshake(client)
  of Socks5:
    result = socks5ProxyHandshake(client)
  of Unknown:
    raise newException(ValueError, "unknown proxy protocol")

# === Client ===

type Client = ref object
  id: Oid
  config: ClientConfig
  sock: Socket
  remoteSock: Socket
  address: (string, uint16)
  remoteAddress: (string, uint16)
  when not defined(pool):
    runThread: Thread[Client]
    downstreamThread: Thread[Client]

func `$`(client: Client): string =
  return
    if client.remoteSock == nil:
      fmt"{client.id}<{client.address}>"
    else:
      fmt"{client.id}<{client.address},{client.remoteAddress}>"

proc close(client: Client) =
  ## close client

  if client.sock != nil:
    client.sock.close()
  if client.remoteSock != nil:
    client.remoteSock.close()

proc connectRemote(client: Client, remoteAddress: (string, uint16)) =
  ## connect to remote
  ##
  ## TODO:
  ## 1. doh resolve remoteAddress

  let remoteSock = newSocket(buffered = false)
  let (host, port) = remoteAddress
  remoteSock.connect(host, port.Port, timeout = client.config.cnnTimeout)
  client.remoteAddress = remoteAddress
  client.remoteSock = remoteSock

proc handleTlsClientHello(client: Client) =
  ## handle TLS client hello
  ##
  ## https://tls13.xargs.org/#client-hello

  let recordHeader = client.sock.recv(5)

  let recordType = recordHeader[0].int
  if recordType != 0x16:
    raise newException(
      ValueError,
      fmt"not a TLS handshake message, record type: {recordType=}, must be 0x16(handshake)",
    )
  let handshakeDataLen = recordHeader[3 ..< 5].be32.int
  let handshakeHeaderLen = 4
  if handshakeDataLen <= handshakeHeaderLen:
    raise newException(ValueError, "invalid a TLS handshake message, too small")

  let handshakeData = client.sock.recv(handshakeDataLen)

  if handshakeData[0].int != 0x01:
    raise newException(ValueError, "not a TLS client hello message")
  let clientHelloDataLen = handshakeData[1 .. 3].be32.int
  if clientHelloDataLen.int != (handshakeDataLen - handshakeHeaderLen):
    raise
      newException(ValueError, "invalid TLS client hello message, inconsistent length")

  # parse TLS client hello
  let (sni, isTls13) = parseTlsClientHello(handshakeData[handshakeHeaderLen .. ^1])
  if not isTls13:
    raise newException(ValueError, "not TLS 1.3")

  assert sni != ""
  info client, ": ", fmt"{sni=}"

  # fragmentize TLS client hello
  let fragmentList = fragmentizeTlsClientHello(handshakeData, sni, recordHeader[..2])
  info client, ": ", fmt"send TLS client hello, {fragmentList.len=}"

  # send fragmentList
  for fragment in fragmentList:
    client.remoteSock.send(fragment)

proc upstreaming(client: Client) =
  ## upstreaming
  ##
  ## TODO:
  ## 1. tls fragment to avoid exposing sni on tls handshake

  var tlsClientHello = true
  while true:
    if tlsClientHello:
      tlsClientHello = false
      info client, ": ", "handling TLS client hello"
      client.handleTlsClientHello()
    else:
      let data = client.sock.recv(16384)
      if data == "":
        raise newException(ValueError, "upstream data is EOF (client is disconnected)")
      debug client, ": ", fmt"upstream {data.len=}"
      debug client, ": ", fmt"upstream {data=}"
      client.remoteSock.send(data)

proc downstreaming(client: Client) =
  ## downstreaming

  while true:
    let data = client.remoteSock.recv(16384)
    if data == "":
      raise newException(
        ValueError, "downstream data is EOF (remote server is disconnected)"
      )
    debug client, ": ", fmt"downstream {data.len=}"
    debug client, ": ", fmt"downstream {data=}"
    client.sock.send(data)

proc downstreamingThreadProc(client: Client) {.thread.} =
  ## a thread proc for downstreaming

  {.gcsafe.}:
    addHandler(logger)
    when defined(pool):
      removeHandler(logger)

  try:
    client.downstreaming()
  except Exception as e:
    if e.msg == "Bad file descriptor":
      return
    error client, ": ", fmt"downstream error: err={e.msg}"
    client.close()

proc streaming(client: Client) =
  ## client streaming
  ##
  ## main steps:
  ## 1. spawn a thread to downstreaming
  ## 2. upstreaming

  debug client, ": ", "spawn to downstreaming"
  when defined(pool):
    spawn downstreamingThreadProc(client)
  else:
    createThread(client.downstreamThread, downstreamingThreadProc, client)

  try:
    debug client, ": ", "upstreaming"
    client.upstreaming()
  except Exception as e:
    if e.msg == "Bad file descriptor":
      return
    raise newException(ValueError, fmt"upstream error: err={e.msg}")

proc handleClient(client: Client) {.thread.} =
  ## handle a new client
  ##
  ## main steps:
  ## 1. handle proxy protocol handshake to get remote server address
  ## 2. connect to remote server address
  ## 3. client streaming

  {.gcsafe.}:
    addHandler(logger)
    when defined(pool):
      removeHandler(logger)

  info client, ": ", "client is connected"

  defer:
    info client, ": ", "client is closed"
    client.close()

  # 1. proxy protocol handshake
  var remoteAddress: (string, uint16)
  try:
    remoteAddress = proxyHandshake(client.sock)
  except Exception as e:
    error client, ": ", fmt"proxy protocol handshake error: err={e.msg}"
    return

  assert remoteAddress != default((string, uint16))

  # 2. client connect to remote server
  try:
    info client, ": ", fmt"connect remote server {remoteAddress}"
    client.connectRemote(remoteAddress)
  except Exception as e:
    error client, ": ", fmt"connect remote server error: err={e.msg}"
    return

  # 3. client streaming
  try:
    client.streaming()
  except Exception as e:
    error client, ": ", fmt"streaming error: err={e.msg}"
    return

# === Server ===

type Server = ref object
  config: ServerConfig
  sock: Socket
  runThread: Thread[Server]
  when not defined(pool):
    clientList: seq[Client]

proc close(server: Server) =
  ## close proxy server

  if server.sock != nil:
    server.sock.close()

proc closeAndWait(server: Server) =
  ## close proxy server and wait for it finished

  server.close()
  if server.runThread.running():
    joinThread(server.runThread)

proc start(server: Server) {.thread.} =
  ## start proxy server

  {.gcsafe.}:
    addHandler(logger)
    when defined(pool):
      removeHandler(logger)

  server.sock = newSocket(buffered = false)
  server.sock.setSockOpt(OptReusePort, true)
  server.sock.setSockOpt(OptReuseAddr, true)
  server.sock.bindAddr(Port(server.config.port), server.config.host)
  server.sock.listen(backlog = server.config.backlog)

  info fmt"server is listening at {server.sock.getLocalAddr()}"

  defer:
    info "server is closed"
    server.sock.close()
    when not defined(pool):
      for client in server.clientList:
        client.close()
      server.clientList.setLen(0)

  while true:
    when not defined(pool):
      server.clientList = server.clientList.filterIt(it.runThread.running())
      info fmt"{server.clientList.len=}"
    {.gcsafe.}:
      var client = Client(config: config.client, id: genOid())
    server.sock.accept(client.sock)
    client.address = client.sock.getPeerAddr()
    when defined(pool):
      spawn handleClient(client)
    else:
      server.clientList.add(client)
      createThread(client.runThread, handleClient, client)

proc startAndWait(server: Server) =
  ## start proxy server and wait for it finished

  createThread(server.runThread, start, server)
  joinThread(server.runThread)

# === Main ===

when defined(pool):
  init(Weave)

var server = Server(config: config.server)
server.startAndWait()

when defined(pool):
  exit(Weave)
