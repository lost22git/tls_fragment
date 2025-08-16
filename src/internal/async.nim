import std/[strformat, strutils, net, asyncnet, asyncdispatch, logging, oids]
import ./common
import ./asyncdoh

echo "=== ASYNC ==="

# === Proxy Protocol Handshake ===

proc guessProxyProtocol(client: AsyncSocket): Future[ProxyProtocol] {.async.} =
  ## guess proxy protocol

  var data = await client.recv(1)
  if data[0].int == 0x05:
    return Socks5
  if data[0] == 'C':
    data = await client.recv(6)
    if data == "ONNECT":
      return Http
  return Unknown

proc socks5ProxyExtractServerAddr(
    client: AsyncSocket
): Future[(string, uint16)] {.async.} =
  ## extract remote server address from socks5 proxy handshake

  let addrType = (await client.recv(1))[0].int
  case addrType
  of 0x01: # IPV4
    var data: array[0 .. 3, uint8]
    discard await client.recvInto(data.addr, 4)
    let ipv4 = IpAddress(family: IPv4, address_v4: data)
    let port = (await client.recv(2)).be16()
    result = ($ipv4, port)
  of 0x03: # Domain name (len(1B)+name)
    let len = (await client.recv(1))[0].int
    let domain = await client.recv(len)
    let port = (await client.recv(2)).be16()
    result = (domain, port)
  of 0x04: # IPV6
    var data: array[0 .. 15, uint8]
    discard await client.recvInto(data.addr, 16)
    let ipv6 = IpAddress(family: IPv6, address_v6: data)
    let port = (await client.recv(2)).be16()
    result = ($ipv6, port)
  else:
    return

proc socks5ProxyHandshake(client: AsyncSocket): Future[(string, uint16)] {.async.} =
  ## handle socks5 proxy handshake
  ##
  ## https://en.m.wikipedia.org/wiki/SOCKS
  ##
  ## NOTE:
  ## we only support tcp and no auth now.

  let clientAddr = client.getPeerAddr()

  # 1. initial request
  let nauth = (await client.recv(1))[0].int
  discard await client.recv(nauth)
  await client.send("\x05\x00") # no auth
  info clientAddr, ": ", fmt"socks5 proxy handshake: auth=0x00(no auth)"

  # 2. auth requeset (skip when no auth)

  # 3. client connection request
  let header = await client.recv(3)
  # echo fmt"{header.repr =}"
  assert header[0].int == 0x05
  let cmd = header[1].int
  case cmd
  of 0x01: # establish a TCP/IP stream connection
    let serverAddr = await socks5ProxyExtractServerAddr(client)
    if serverAddr == default((string, uint16)):
      await client.send("\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
      raise newException(
        ValueError, "socks5 proxy handshake error: address type not supported"
      )
    else:
      info clientAddr, ": ", fmt"socks5 proxy handshake: {serverAddr=}"
      await client.send("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
      return serverAddr
  else:
    await client.send("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
    raise newException(
      ValueError,
      fmt"socks5 proxy handshake error: command({cmd}) not supported / protocol error",
    )

proc httpProxyExtractServerAddr(
    client: AsyncSocket
): Future[(string, uint16)] {.async.} =
  ## extract remote server address from http proxy handshake
  ##
  ## NOTE:
  ## we find remote server address from `Host` header,
  ## and not authentication support now.

  var line = ""
  while true:
    line = await client.recvLine()
    if line == "\r\n":
      return
    if line.startsWith("Host: "):
      let split = line[6 ..^ 1].split(":")
      result = (split[0], split[1].parseInt().uint16)

proc httpProxyHandshake(client: AsyncSocket): Future[(string, uint16)] {.async.} =
  ## handle http proxy handshake

  let clientAddr = client.getPeerAddr()
  let serverAddr = await httpProxyExtractServerAddr(client)
  if serverAddr == default((string, uint16)):
    await client.send("HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n")
    raise newException(ValueError, "http proxy handshake error: serverAddr not found")
  info clientAddr, ": ", fmt"http proxy handshake: {serverAddr=}"
  await client.send(
    "HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
  )
  return serverAddr

proc proxyHandshake(client: AsyncSocket): Future[(string, uint16)] {.async.} =
  ## handle proxy handshake
  ##
  ## supported proxy protocols:
  ## 1. http
  ## 2. socks5

  case await guessProxyProtocol(client)
  of Http:
    result = await httpProxyHandshake(client)
  of Socks5:
    result = await socks5ProxyHandshake(client)
  of Unknown:
    raise newException(ValueError, "unknown proxy protocol")

# === Client ===

type Client = ref object
  id: Oid
  config: ClientConfig
  sock: AsyncSocket
  remoteSock: AsyncSocket
  address: (string, uint16)
  remoteAddress: (string, uint16)
  doh: Doh

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

proc connectRemote(client: Client, remoteAddress: (string, uint16)) {.async.} =
  ## connect to remote

  # resolve ip via DoH
  var host = ""
  let domain = remoteAddress[0]
  try:
    host = await client.doh.resolve(domain)
    info client, ": ", fmt"DoH resolved: {domain} -> {host}"
  except Exception as e:
    raise newException(ValueError, fmt"DoH resolve error, {domain=}, err={e.msg}")

  # connect remote
  let remoteSock = newAsyncSocket(buffered = false)
  remoteSock.setSockOpt(OptNoDelay, true, level = IPPROTO_TCP.cint)
  await remoteSock.connect(host, 443.Port)

  # bind info to client
  client.remoteAddress = remoteAddress
  client.remoteSock = remoteSock

proc handleTlsClientHello(client: Client) {.async.} =
  ## handle TLS client hello
  ##
  ## https://tls13.xargs.org/#client-hello

  let recordHeader = await client.sock.recv(5)

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
  info client, ": ", fmt"{sni=}"

  # fragmentize TLS client hello
  let fragmentList = fragmentizeTlsClientHello(handshakeData, sni, recordHeader[0 .. 2])
  info client, ": ", fmt"send TLS client hello, {fragmentList.len=}"

  # send fragmentList
  for fragment in fragmentList:
    await sleepAsync 10
    await client.remoteSock.send(fragment)

proc upstreaming(client: Client) {.async.} =
  ## upstreaming

  while true:
    let data = await client.sock.recv(16384)
    if data == "":
      raise newException(ValueError, "upstream data is EOF (client is disconnected)")
    debug client, ": ", fmt"upstream {data.len=}"
    debug client, ": ", fmt"upstream {data=}"
    await client.remoteSock.send(data)

proc downstreaming(client: Client) {.async.} =
  ## downstreaming

  while true:
    let data = await client.remoteSock.recv(16384)
    if data == "":
      raise newException(
        ValueError, "downstream data is EOF (remote server is disconnected)"
      )
    debug client, ": ", fmt"downstream {data.len=}"
    debug client, ": ", fmt"downstream {data=}"
    await client.sock.send(data)

proc downstreamingThreadProc(client: Client) {.async.} =
  ## a thread proc for downstreaming

  try:
    await client.downstreaming()
  except Exception as e:
    if e.msg != "Bad file descriptor":
      error client, ": ", fmt"downstream error: err={e.msg}"
    client.close()

proc handleClient(client: Client) {.async.} =
  ## handle a new client

  defer:
    info client, ": ", "client is closed"
    client.close()

  # 1. proxy handshake
  var remoteAddress: (string, uint16)
  try:
    remoteAddress = await proxyHandshake(client.sock)
  except Exception as e:
    error client, ": ", fmt"proxy handshake error: err={e.msg}"
    return

  assert remoteAddress != default((string, uint16))

  # 2. client connect to remote server
  try:
    info client, ": ", fmt"connect remote server {remoteAddress}"
    await client.connectRemote(remoteAddress)
  except Exception as e:
    error client, ": ", fmt"connect remote server error: {remoteAddress}, err={e.msg}"
    return

  # 3. handle tls client hello
  try:
    info client, ": ", "TLS client hello"
    await client.handleTlsClientHello()
  except Exception as e:
    error client, ": ", fmt"TLS client hello error, err={e.msg}"
    return

  # 4. spawn downstreaming
  try:
    debug client, ": ", "spawn downstreaming"
    asyncCheck downstreamingThreadProc(client)
  except Exception as e:
    error client, ": ", fmt"failed to spawn downstreaming, err={e.msg}"
    return

  # 5. upstreaming
  try:
    debug client, ": ", "upstreaming"
    await client.upstreaming()
  except Exception as e:
    if e.msg != "Bad file descriptor":
      error client, ": ", fmt"upstream error: err={e.msg}"
    return

# === Server ===

type Server = ref object
  config: ServerConfig
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
  server.sock.bindAddr(Port(server.config.port), server.config.host)
  server.sock.listen(backlog = server.config.backlog)

  info fmt"server is listening at {server.sock.getLocalAddr()}"

  let doh = newDoh(proxyUrl = fmt"http://{server.config.host}:{server.config.port}")

  defer:
    info "server is closed"
    server.sock.close()

  while true:
    {.gcsafe.}:
      var client = Client(config: config.client, id: genOid())
    let clientSock = await server.sock.accept()
    client.sock = clientSock
    client.address = client.sock.getPeerAddr()
    client.doh = doh
    asyncCheck handleClient(client)

# === Main ===

var server = Server(config: config.server)
asyncCheck server.start()
runForever()
