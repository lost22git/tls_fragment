import std/[asyncdispatch, httpclient, json, strutils, strformat, sequtils]

type Doh* = ref object
  proxy: Proxy

let remoteUrl = "https://cloudflare-dns.com/dns-query?name=$1&type=$2"

proc newDoh*(proxyUrl: string): Doh =
  return Doh(proxy: newProxy(url = proxyUrl))

proc resolveFromRemote*(
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
  debug fmt"DoH resolve from remote: response {data=}"

  let jsonObj = parseJson(data)
  let answerList = jsonObj["Answer"]
  let ipAnswerList = answerList.filterIt(it["type"].getInt == 1)
  doAssert ipAnswerList.len != 0

  let firstAnswer = ipAnswerList[0]
  return (firstAnswer["data"].getStr, firstAnswer["TTL"].getInt)

proc resolve*(doh: Doh, qDomain: string): Future[string] {.async.} =
  if qDomain in ["cloudflare-dns.com", "one.one.one.one"]:
    return "104.16.249.249"
  let (ip, ttl) = await resolveFromRemote(doh, qDomain, qType)
  return ip
