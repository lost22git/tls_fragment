import
  std/[
    asyncdispatch, httpclient, json, strutils, strformat, sequtils, logging, strtabs,
    times,
  ]

type Doh* = ref object
  proxy: Proxy
  cache: StringTableRef = newStringTable(modeCaseInsensitive)

let remoteUrl = "https://cloudflare-dns.com/dns-query?name=$1&type=$2"

proc newDoh*(proxyUrl: string): Doh =
  return Doh(proxy: newProxy(url = proxyUrl))

proc cacheRecord(doh: Doh, qDomain: string, ip: string, ttl: int) =
  let exp = getTime().toUnix() + (ttl - 10)
  doh.cache[qDomain] = ip & "/" & $exp

proc resolveViaCache(doh: Doh, qDomain: string): string =
  let value = doh.cache.getOrDefault(qDomain, "")
  if value == "":
    return ""
  let ipAndExp = split(value, "/")
  let (ip, exp) = (ipAndExp[0], ipAndExp[1])
  if exp.parseInt() < getTime().toUnix():
    return ""
  return ip

proc resolveViaRemote(
    doh: Doh, qDomain: string, qType: string
): Future[(string, int)] {.async.} =
  let url = remoteUrl % [qDomain, qType]

  let client = newAsyncHttpClient(proxy = doh.proxy)
  defer:
    client.close()

  let response = await client.request(
    url = url,
    httpmethod = HttpGet,
    headers = newHttpHeaders({"Accept": "application/dns-json"}),
  )
  let data = await response.body()
  debug fmt"DoH resolve via remote: response {data=}"

  let jsonObj = parseJson(data)
  let answerList = jsonObj["Answer"]
  let ipAnswerList = answerList.filterIt(it["type"].getInt == 1)
  doAssert ipAnswerList.len != 0

  let firstAnswer = ipAnswerList[0]
  return (firstAnswer["data"].getStr, firstAnswer["TTL"].getInt)

proc resolve*(doh: Doh, qDomain: string): Future[string] {.async.} =
  if qDomain in ["cloudflare-dns.com", "one.one.one.one"]:
    return "104.16.249.249"

  # check cache
  if (let ip = doh.resolveViaCache(qDomain); ip != ""):
    info fmt"DoH cache hit: {qDomain} -> {ip}"
    return ip

  info fmt"DoH resolved via cache failed, maybe not found or expired, trying resolve via remote {qDomain=}"

  # check remote
  let (ip, ttl) = await doh.resolveViaRemote(qDomain, "A")
  doh.cacheRecord(qDomain, ip, ttl)
  return ip
