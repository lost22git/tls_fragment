import std/[asyncdispatch, httpclient, json, strutils, sequtils, strtabs, tables, times]
import chronicles

type CacheLoader = proc(k: string): Future[string] {.async, closure.}

type Cache = ref object
  tab: StringTableRef # store domain -> ip/expiredTime
  loader: CacheLoader
  loadingFutTab: TableRef[string, Future[void]]

proc newCache(loader: CacheLoader): Cache =
  result = Cache(
    tab: newStringTable(modeCaseInsensitive),
    loader: loader,
    loadingFutTab: newTable[string, Future[void]](),
  )

proc get(cache: Cache, key: string): Future[string] {.async.} =
  if cache.tab.contains(key):
    let value = cache.tab[key]
    debug "DoH cache hit", key, value
    return value

  if cache.loadingFutTab.contains(key):
    await cache.loadingFutTab[key]
    return await cache.get(key)

  let loadingFut = newFuture[void]("DoH cache loading future: key=" & $key)
  cache.loadingFutTab[key] = loadingFut
  try:
    debug "DoH cache loading", key
    let value = await cache.loader(key)
    cache.tab[key] = value
    return value
  finally:
    loadingFut.complete()
    cache.loadingFutTab.del key

proc del(cache: Cache, key: string) =
  cache.tab.del key

type Doh* = ref object
  proxy: Proxy
  cache: Cache

let dohUrl = "https://cloudflare-dns.com/dns-query?name=$1&type=$2"

proc resolveViaRemote(
    doh: Doh, qDomain: string, qType: string
): Future[string] {.async.} =
  let url = dohUrl % [qDomain, qType]

  let client = newAsyncHttpClient(proxy = doh.proxy)
  defer:
    client.close()

  let response = await client.request(
    url = url,
    httpmethod = HttpGet,
    headers = newHttpHeaders({"Accept": "application/dns-json"}),
  )
  let data = await response.body()
  debug "DoH resolve via remote", qDomain, data

  let jsonObj = parseJson(data)
  let answerList = jsonObj["Answer"]
  let t = if qType == "AAAA": 28 else: 1
  let ipAnswerList = answerList.filterIt(it["type"].getInt == t)
  doAssert ipAnswerList.len != 0

  let firstAnswer = ipAnswerList[0]
  let ip = firstAnswer["data"].getStr
  let exp = getTime().toUnix() + firstAnswer["TTL"].getInt - 10 # expires 10s in advance
  return $ip & "/" & $exp

proc resolveViaCache(doh: Doh, domainAndType: string): Future[string] {.async.} =
  let value = await doh.cache.get(domainAndType)
  let ipAndExp = split(value, "/")
  let (ip, exp) = (ipAndExp[0], ipAndExp[1])
  if exp.parseInt() < getTime().toUnix():
    doh.cache.del domainAndType
    info "DoH resolved via cache failed, maybe expired, try again", domainAndType
    return await resolveViaCache(doh, domainAndType)
  return ip

proc newDoh*(proxyUrl: string): Doh =
  let doh = Doh(proxy: newProxy(url = proxyUrl))
  doh.cache = newCache(
    loader = proc(k: string): Future[string] {.async, closure.} =
      let domainAndType = k.split("/")
      return await doh.resolveViaRemote(domainAndType[0], domainAndType[1])
  )
  return doh

proc resolve*(
    doh: Doh, qDomain: string, qType: string = "A"
): Future[string] {.async.} =
  if qDomain in ["cloudflare-dns.com", "one.one.one.one"] and qType == "A":
    return "104.16.249.249"
  return await doh.resolveViaCache(qDomain & "/" & qType)
