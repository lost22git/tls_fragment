import std/[strformat, strutils, sequtils, net, typedThreads, oids, json]
import ./common
import ./syncdoh
import chronicles

when defined(pool):
  import weave

when defined(pool):
  echo "=== POOL ==="
else:
  echo "=== SYNC ==="

# === Client ===

type Client = ref object
  id: Oid
  config: ClientConfig
  sock: Socket
  remoteSock: Socket
  address: (string, uint16)
  remoteAddress: (string, uint16)
  proxyProtocol: ProxyProtocol
  when not defined(pool):
    runThread: Thread[Client]
    downstreamThread: Thread[Client]
  doh: Doh
  policy: JsonNode

proc close(client: Client) =
  ## close client

  if client.sock != nil:
    client.sock.close()
  if client.remoteSock != nil:
    client.remoteSock.close()

proc guessProxyProtocol(client: Client): ProxyProtocol =
  ## guess proxy protocol

  var data = client.sock.recv(1)
  if data[0].int == 0x05:
    return Socks5
  if data[0] == 'C':
    data = client.sock.recv(6)
    if data == "ONNECT":
      return Http
  if data[0].int == 0x16:
    return None
  return Unknown

proc socks5ProxyExtractRemoteAddr(client: Client): (string, uint16) =
  ## extract remote server address from socks5 proxy handshake

  let addrType = client.sock.recv(1)[0].int
  case addrType
  of 0x01: # IPV4
    var data: array[0 .. 3, uint8]
    discard client.sock.recv(data.addr, 4)
    let ipv4 = IpAddress(family: IPv4, address_v4: data)
    let port = client.sock.recv(2).be16()
    result = ($ipv4, port)
  of 0x03: # Domain name (len(1B)+name)
    let len = client.sock.recv(1)[0].int
    let domain = client.sock.recv(len)
    let port = client.sock.recv(2).be16()
    result = (domain, port)
  of 0x04: # IPV6
    var data: array[0 .. 15, uint8]
    discard client.sock.recv(data.addr, 16)
    let ipv6 = IpAddress(family: IPv6, address_v6: data)
    let port = client.sock.recv(2).be16()
    result = ($ipv6, port)
  else:
    return

proc socks5ProxyHandshake(client: Client): (string, uint16) =
  ## handle socks5 proxy handshake
  ##
  ## https://en.m.wikipedia.org/wiki/SOCKS
  ##
  ## NOTE:
  ## we only support tcp and no auth now.

  logClient()

  # 1. initial request
  let nauth = client.sock.recv(1)[0].int
  discard client.sock.recv(nauth)
  client.sock.send("\x05\x00") # no auth
  info "socks5 proxy handshake: auth=0x00(no auth)"

  # 2. auth requeset (skip when no auth)

  # 3. client connection request
  let header = client.sock.recv(3)
  # echo fmt"{header.repr =}"
  assert header[0].int == 0x05
  let cmd = header[1].int
  case cmd
  of 0x01: # establish a TCP/IP stream connection
    let remoteAddr = socks5ProxyExtractRemoteAddr(client)
    if remoteAddr == default((string, uint16)):
      client.sock.send("\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
      raise newException(
        ValueError, "socks5 proxy handshake error: address type not supported"
      )
    else:
      info "socks5 proxy handshake: extracted remote addresss", remoteAddr
      client.sock.send("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
      return remoteAddr
  else:
    client.sock.send("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
    raise newException(
      ValueError,
      fmt"socks5 proxy handshake error: command({cmd}) not supported / protocol error",
    )

proc httpProxyExtractRemoteAddr(client: Client): (string, uint16) =
  ## extract remote server address from http proxy handshake
  ##
  ## NOTE:
  ## we find remote server address from `Host` header,
  ## and not authentication support now.

  var line = ""
  while true:
    client.sock.readLine(line)
    if line == "\r\n":
      return
    if line.startsWith("Host: "):
      let split = line[6 ..^ 1].split(":")
      result = (split[0], split[1].parseInt().uint16)

proc httpProxyHandshake(client: Client): (string, uint16) =
  ## handle http proxy handshake

  logClient()

  let remoteAddr = httpProxyExtractRemoteAddr(client)
  if remoteAddr == default((string, uint16)):
    client.sock.send("HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n")
    raise newException(ValueError, "http proxy handshake error: remoteAddr not found")
  info "http proxy handshake: extracted remote address", remoteAddr
  client.sock.send(
    "HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
  )
  return remoteAddr

proc proxyHandshake(client: Client): (string, uint16) =
  ## handle proxy handshake
  ##
  ## supported proxy protocols:
  ## 1. http
  ## 2. socks5

  let proxyProtocol = guessProxyProtocol(client)
  client.proxyProtocol = proxyProtocol
  case proxyProtocol
  of Http:
    result = httpProxyHandshake(client)
  of Socks5:
    result = socks5ProxyHandshake(client)
  of None:
    discard
  of Unknown:
    raise newException(ValueError, "unknown proxy protocol")

proc processTlsClientHello(client: Client): (string, seq[string]) =
  ## process TLS client hello
  ##
  ## https://tls13.xargs.org/#client-hello

  logClient()

  let recordHeader =
    if client.proxyProtocol == None:
      "\x16" & client.sock.recv(4)
    else:
      client.sock.recv(5)

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
  info "sni parsed", sni

  # fragmentize TLS client hello
  let fragmentList = fragmentizeTlsClientHello(handshakeData, sni, recordHeader[0 .. 2])

  return (sni, fragmentList)

proc connectRemote(client: Client) =
  ## connect to remote

  logClient()

  var host = client.policy.getOrDefault("IP").getStr()
  var port = client.policy.getOrDefault("port").getInt(443).uint16
  let af =
    if client.policy.getOrDefault("IPtype").getStr() == "ipv6": AF_INET6 else: AF_INET

  # resolve ip via DoH
  if host == "":
    let domain = client.remoteAddress[0]
    let qType = if af == AF_INET6: "AAAA" else: "A"
    try:
      {.gcsafe.}:
        host = client.doh.resolve(domain, qType)
      info "DoH resolved", domain, qType, host
    except Exception as e:
      raise newException(ValueError, fmt"DoH resolve error: {domain=}, err={e.msg}")

  info "connect to remote", af, host, port
  let remoteSock = newSocket(domain = af, buffered = false)
  remoteSock.setSockOpt(OptNoDelay, true, level = IPPROTO_TCP.cint)
  remoteSock.connect(host, Port(port), timeout = client.config.cnnTimeout)
  client.remoteSock = remoteSock

proc upstreaming(client: Client) =
  ## upstreaming

  logClient()

  while true:
    let data = client.sock.recv(16384)
    if data == "":
      raise newException(ValueError, "upstreaming data is EOF (client is disconnected)")
    debug "upstreaming", dataLen = data.len
    debug "upstreaming", data
    client.remoteSock.send(data)

proc downstreaming(client: Client) {.thread.} =
  ## downstreaming

  logClient()

  try:
    while true:
      let data = client.remoteSock.recv(16384)
      if data == "":
        raise newException(
          ValueError, "downstreaming data is EOF (remote server is disconnected)"
        )
      debug "downstreaming", dataLen = data.len
      debug "downstreaming", data
      client.sock.send(data)
  except Exception as err:
    if err.msg != "Bad file descriptor":
      error "downstreaming error", err
    client.close()

proc handleClient(client: Client) {.thread.} =
  ## handle a new client

  logClient()

  defer:
    info "client is closed"
    client.close()

  # 1. proxy handshake
  var remoteAddress: (string, uint16)
  try:
    remoteAddress = client.proxyHandshake()
  except Exception as err:
    error "proxy handshake error", err
    return

  # 2. process TLS client hello
  var tlsClientHelloData: (string, seq[string])
  try:
    tlsClientHelloData = client.processTlsClientHello()
  except Exception as err:
    error "process TLS client hello error", err
    return

  let (sni, fragmentList) = tlsClientHelloData
  if client.proxyProtocol == None or isIpAddress(remoteAddress[0]):
    remoteAddress = (sni, 443)

  client.remoteAddress = remoteAddress
  client.policy = getPolicy(client.remoteAddress[0])
  info "policy used", policy = client.policy.pretty()

  # 3. client connect to remote
  try:
    client.connectRemote()
  except Exception as err:
    error "connect to remote error", err
    return

  # 4. send tls client hello
  try:
    info "send TLS client hello", fragmentListLen = fragmentList.len
    for fragment in fragmentList:
      client.remoteSock.send(fragment)
  except Exception as err:
    error "send TLS client hello error", err
    return

  # 5. spawn downstreaming
  try:
    when defined(pool):
      spawn client.downstreaming()
    else:
      createThread(client.downstreamThread, downstreaming, client)
  except Exception as err:
    error "failed to spawn downstreaming", err
    return

  # 6. upstreaming
  try:
    client.upstreaming()
  except Exception as err:
    if err.msg != "Bad file descriptor":
      error "upstreaming error", err
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

  server.sock = newSocket(buffered = false)
  server.sock.setSockOpt(OptReusePort, true)
  server.sock.setSockOpt(OptReuseAddr, true)
  server.sock.bindAddr(Port(server.config.port), server.config.host)
  server.sock.listen(backlog = server.config.backlog)

  info "server is listening", address = server.sock.getLocalAddr()

  let doh = newDoh(proxyUrl = fmt"http://{server.config.host}:{server.config.port}")

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
      info "client list", len = server.clientList.len
    {.gcsafe.}:
      var client = Client(config: common.config.client, id: genOid())
    server.sock.accept(client.sock)
    client.address = client.sock.getPeerAddr()
    client.doh = doh
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

var server = Server(config: common.config.server)
server.startAndWait()

when defined(pool):
  exit(Weave)
