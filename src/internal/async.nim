import std/[strformat, strutils, net, asyncnet, asyncdispatch, logging, oids]
import ./common
import ./asyncdoh

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

  # 1. initial request
  let nauth = (await client.sock.recv(1))[0].int
  discard await client.sock.recv(nauth)
  await client.sock.send("\x05\x00") # no auth
  info client, ": ", fmt"socks5 proxy handshake: auth=0x00(no auth)"

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
      info client, ": ", fmt"socks5 proxy handshake: {remoteAddr=}"
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

  let remoteAddr = await httpProxyExtractRemoteAddr(client)
  if remoteAddr == default((string, uint16)):
    await client.sock.send(
      "HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
    )
    raise newException(ValueError, "http proxy handshake error: remoteAddr not found")
  info client, ": ", fmt"http proxy handshake: {remoteAddr=}"
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

proc processTlsClientHello(client: Client): Future[(string, seq[string])] {.async.} =
  ## process TLS client hello
  ##
  ## https://tls13.xargs.org/#client-hello

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
  info client, ": ", fmt"{sni=}"

  # fragmentize TLS client hello
  let fragmentList = fragmentizeTlsClientHello(handshakeData, sni, recordHeader[0 .. 2])

  return (sni, fragmentList)

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
    remoteAddress = await client.proxyHandshake()
  except Exception as e:
    error client, ": ", fmt"proxy handshake error: err={e.msg}"
    return

  # 2. process TLS client hello
  info client, ": ", "process TLS client hello"
  var tlsClientHelloData: (string, seq[string])
  try:
    tlsClientHelloData = await client.processTlsClientHello()
  except Exception as e:
    error client, ": ", fmt"process TLS client hello error: err={e.msg}"
    return

  let (sni, fragmentList) = tlsClientHelloData
  if client.proxyProtocol == None:
    remoteAddress = (sni, 443)

  assert remoteAddress != default((string, uint16))

  # 3. client connect to remote server
  try:
    info client, ": ", fmt"connect remote server {remoteAddress}"
    await client.connectRemote(remoteAddress)
  except Exception as e:
    error client, ": ", fmt"connect remote server error: {remoteAddress}, err={e.msg}"
    return

  # 4. send tls client hello
  try:
    info client, ": ", fmt"send TLS client hello, {fragmentList.len=}"
    for fragment in fragmentList:
      await sleepAsync 10
      await client.remoteSock.send(fragment)
  except Exception as e:
    error client, ": ", fmt"send TLS client hello error, err={e.msg}"
    return

  # 5. spawn downstreaming
  try:
    debug client, ": ", "spawn downstreaming"
    asyncCheck downstreamingThreadProc(client)
  except Exception as e:
    error client, ": ", fmt"failed to spawn downstreaming, err={e.msg}"
    return

  # 6. upstreaming
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
