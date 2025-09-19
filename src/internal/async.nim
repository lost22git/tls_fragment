import std/[strformat, strutils, net, asyncnet, asyncdispatch, oids, json]
import ./common
import ./asyncdoh
import chronicles

echo "=== ASYNC ==="

# === Client ===

type Client = ref object
  id: Oid
  config: ClientConfig
  sock: AsyncSocket
  remoteSock: AsyncSocket
  address: (string, uint16)
  remoteAddress: (string, uint16)
  proxyProtocol: ProxyProtocol
  doh: Doh
  policy: JsonNode

proc close(client: Client) =
  ## close client

  if client.sock != nil:
    client.sock.close()
  if client.remoteSock != nil:
    client.remoteSock.close()

proc guessProxyProtocol(client: Client): Future[ProxyProtocol] {.async.} =
  ## guess proxy protocol

  var data = await client.sock.recv(1)
  if data[0].int == 0x05:
    return Socks5
  if data[0] == 'C':
    data = await client.sock.recv(6)
    if data == "ONNECT":
      return Http
  if data[0].int == 0x16: # tls record: type=handshake
    return None
  return Unknown

proc socks5ProxyExtractRemoteAddr(client: Client): Future[(string, uint16)] {.async.} =
  ## extract remote server address from socks5 proxy handshake

  let addrType = (await client.sock.recv(1))[0].int
  case addrType
  of 0x01: # IPV4
    var data: array[0 .. 3, uint8]
    discard await client.sock.recvInto(data.addr, 4)
    let ipv4 = IpAddress(family: IPv4, address_v4: data)
    let port = (await client.sock.recv(2)).be16()
    result = ($ipv4, port)
  of 0x03: # Domain name (len(1B)+name)
    let len = (await client.sock.recv(1))[0].int
    let domain = await client.sock.recv(len)
    let port = (await client.sock.recv(2)).be16()
    result = (domain, port)
  of 0x04: # IPV6
    var data: array[0 .. 15, uint8]
    discard await client.sock.recvInto(data.addr, 16)
    let ipv6 = IpAddress(family: IPv6, address_v6: data)
    let port = (await client.sock.recv(2)).be16()
    result = ($ipv6, port)
  else:
    return

proc socks5ProxyHandshake(client: Client): Future[(string, uint16)] {.async.} =
  ## handle socks5 proxy handshake
  ##
  ## https://en.m.wikipedia.org/wiki/SOCKS
  ##
  ## NOTE:
  ## we only support tcp and no auth now.

  logClient()

  # 1. initial request
  let nauth = (await client.sock.recv(1))[0].int
  discard await client.sock.recv(nauth)
  await client.sock.send("\x05\x00") # no auth
  info "socks5 proxy handshake: auth=0x00(no auth)"

  # 2. auth requeset (skip when no auth)

  # 3. client connection request
  let header = await client.sock.recv(3)
  # echo fmt"{header.repr =}"
  assert header[0].int == 0x05
  let cmd = header[1].int
  case cmd
  of 0x01: # establish a TCP/IP stream connection
    let remoteAddr = await socks5ProxyExtractRemoteAddr(client)
    if remoteAddr == default((string, uint16)):
      await client.sock.send("\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
      raise newException(
        ValueError, "socks5 proxy handshake error: address type not supported"
      )
    else:
      info "socks5 proxy handshake: extracted remote address", remoteAddr
      await client.sock.send("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
      return remoteAddr
  else:
    await client.sock.send("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
    raise newException(
      ValueError,
      fmt"socks5 proxy handshake error: command({cmd}) not supported / protocol error",
    )

proc httpProxyExtractRemoteAddr(client: Client): Future[(string, uint16)] {.async.} =
  ## extract remote server address from http proxy handshake
  ##
  ## NOTE:
  ## we find remote server address from `Host` header,
  ## and not authentication support now.

  var line = ""
  while true:
    line = await client.sock.recvLine()
    if line == "\r\n":
      return
    if line.startsWith("Host: "):
      let split = line[6 ..^ 1].split(":")
      result = (split[0], split[1].parseInt().uint16)

proc httpProxyHandshake(client: Client): Future[(string, uint16)] {.async.} =
  ## handle http proxy handshake

  logClient()

  let remoteAddr = await httpProxyExtractRemoteAddr(client)
  if remoteAddr == default((string, uint16)):
    await client.sock.send(
      "HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
    )
    raise newException(ValueError, "http proxy handshake error: remoteAddr not found")
  info "http proxy handshake: extracted remote address", remoteAddr
  await client.sock.send(
    "HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
  )
  return remoteAddr

proc proxyHandshake(client: Client): Future[(string, uint16)] {.async.} =
  ## handle proxy handshake
  ##
  ## supported proxy protocols:
  ## 1. http
  ## 2. socks5

  let proxyProtocol = await guessProxyProtocol(client)
  client.proxyProtocol = proxyProtocol
  case proxyProtocol
  of Http:
    result = await httpProxyHandshake(client)
  of Socks5:
    result = await socks5ProxyHandshake(client)
  of None:
    discard
  of Unknown:
    raise newException(ValueError, "unknown proxy protocol")

proc processTlsClientHello(client: Client): Future[(string, seq[string])] {.async.} =
  ## process TLS client hello
  ##
  ## https://tls13.xargs.org/#client-hello

  logClient()

  let recordHeader =
    if client.proxyProtocol == None:
      "\x16" & (await client.sock.recv(4))
    else:
      await client.sock.recv(5)

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

  let handshakeData = await client.sock.recv(handshakeDataLen)

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

proc connectRemote(client: Client) {.async.} =
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
      host = await client.doh.resolve(domain, qType)
      info "DoH resolved", domain, qType, host
    except Exception as e:
      raise newException(ValueError, fmt"DoH resolve error: {domain=}, err={e.msg}")

  # connect remote
  info "connect to remote", af, host, port
  let remoteSock = newAsyncSocket(domain = af, buffered = false)
  remoteSock.setSockOpt(OptNoDelay, true, level = IPPROTO_TCP.cint)
  await remoteSock.connect(host, Port(port))

  # bind info to client
  client.remoteSock = remoteSock

proc upstreaming(client: Client) {.async.} =
  ## upstreaming

  logClient()

  while true:
    let data = await client.sock.recv(16384)
    if data == "":
      raise newException(ValueError, "upstreaming data is EOF (client is disconnected)")
    debug "upstreaming", dataLen = data.len
    debug "upstreaming", data
    await client.remoteSock.send(data)

proc downstreaming(client: Client) {.async.} =
  ## downstreaming

  logClient()

  try:
    while true:
      let data = await client.remoteSock.recv(16384)
      if data == "":
        raise newException(
          ValueError, "downstreaming data is EOF (remote server is disconnected)"
        )
      debug "downstreaming", dataLen = data.len
      debug "downstreaming", data
      await client.sock.send(data)
  except Exception as err:
    if err.msg != "Bad file descriptor":
      error "downstreaming error", err
    client.close()

proc handleClient(client: Client) {.async.} =
  ## handle a new client

  logClient()

  defer:
    info "client closed"
    client.close()

  # 1. proxy handshake
  var remoteAddress: (string, uint16)
  try:
    remoteAddress = await client.proxyHandshake()
  except Exception as err:
    error "proxy handshake error", err
    return

  # 2. process TLS client hello
  var tlsClientHelloData: (string, seq[string])
  try:
    tlsClientHelloData = await client.processTlsClientHello()
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
    await client.connectRemote()
  except Exception as err:
    error "connect to remote error", err
    return

  # 4. send tls client hello
  try:
    info "send TLS client hello", fragmentListLen = fragmentList.len
    for fragment in fragmentList:
      await sleepAsync 10
      await client.remoteSock.send(fragment)
  except Exception as err:
    error "send TLS client hello error", err
    return

  # 5. spawn downstreaming
  try:
    asyncCheck client.downstreaming()
  except Exception as err:
    error "failed to spawn downstreaming", err
    return

  # 6. upstreaming
  try:
    await client.upstreaming()
  except Exception as err:
    if err.msg != "Bad file descriptor":
      error "upstreaming error", err
    return

# === Server ===

type Server = ref object
  config: Config
  sock: AsyncSocket

proc close(server: Server) =
  ## close proxy server

  if server.sock != nil:
    server.sock.close()

proc start(server: Server) {.async.} =
  ## start proxy server

  server.sock = newAsyncSocket(buffered = false)
  server.sock.setSockOpt(OptReusePort, true)
  server.sock.setSockOpt(OptReuseAddr, true)
  server.sock.bindAddr(Port(server.config.server.port), server.config.server.host)
  server.sock.listen(backlog = server.config.server.backlog)

  info "server listening", address = server.sock.getLocalAddr()

  let doh = newDoh(
    proxyUrl = fmt"http://{server.config.server.host}:{server.config.server.port}"
  )

  defer:
    info "server closed"
    server.sock.close()

  while true:
    var client = Client(config: server.config.client, id: genOid())
    let clientSock = await server.sock.accept()
    client.sock = clientSock
    client.address = client.sock.getPeerAddr()
    client.doh = doh
    asyncCheck handleClient(client)

# === Main ===

var server = Server(config: common.config)
asyncCheck server.start()
runForever()
