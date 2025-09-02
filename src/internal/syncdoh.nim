import std/[math, cpuinfo, sequtils, hashes, locks]
import std/[httpclient, json, strutils, sequtils, tables, times]
import threading/rwlock
import chronicles

# === LazyValue ===

type LazyValueObj[T, A] = object
  lock: Lock
  completed: bool
  value: T
  loader: proc(arg: A): T
  loaderArg: A

type LazyValue[T, A] = ref LazyValueObj[T, A]

proc `=destroy`[T, A](lazyValue: var LazyValueObj[T, A]) =
  deinitLock(lazyValue.lock)

proc newLazyValue[T, A](loader: proc(arg: A): T, loaderArg: A): LazyValue[T, A] =
  result = LazyValue[T, A](loader: loader, loaderArg: loaderArg)
  initLock(result.lock)

proc get[T, A](lazyValue: LazyValue[T, A]): T =
  if lazyValue.completed:
    return lazyValue.value
  withLock lazyValue.lock:
    if lazyValue.completed:
      return lazyValue.value
    lazyValue.value = lazyValue.loader(lazyValue.loaderArg)
    lazyValue.completed = true
    return lazyValue.value

# === DashTable ===

type Shard[K, V] = ref object
  lock: RwLock
  tab: TableRef[K, V]

proc newShard[K, V](): Shard[K, V] =
  Shard[K, V](lock: createRwLock(), tab: newTable[K, V]())

type DashTable[K, V] = ref object
  shards: seq[Shard[K, V]]

let defaultShards = (max(1, countProcessors()) * 4).nextPowerOfTwo()

proc myhash[K, V](table: DashTable[K, V], key: K): Hash =
  hashes.hash(key)

proc shardWithIndex[K, V](
    table: DashTable[K, V], key: K
): (int, Shard[K, V]) {.inline.} =
  let index = table.myhash(key) and table.shards.high
  (index, table.shards[index])

proc hasKey[K, V](table: DashTable[K, V], key: K): bool =
  let (_, shard) = table.shardWithIndex(key)
  readWith shard.lock:
    result = shard.tab.hasKey(key)

proc get[K, V](table: DashTable[K, V], key: K, f: proc(key: K): V): V {.effectsOf: f.} =
  let (_, shard) = table.shardWithIndex(key)
  readWith shard.lock:
    if shard.tab.hasKey(key):
      return shard.tab[key]
  # key not found
  return f(key)

proc get[K, V](table: DashTable[K, V], key: K): V {.raises: [KeyError].} =
  get(table, key) do(key: K) -> V:
    raise newException(KeyError, "key=" & key)

proc del[K, V](table: DashTable[K, V], key: K) =
  if not table.hasKey(key):
    return
  let (_, shard) = table.shardWithIndex(key)
  writeWith shard.lock:
    shard.tab.del(key)

proc getOrAdd[K, V](
    table: DashTable[K, V], key: sink K, f: proc(key: K): V
): V {.effectsOf: f.} =
  try:
    return table.get(key)
  except KeyError:
    discard

  let (_, shard) = table.shardWithIndex(key)
  writeWith shard.lock:
    if shard.tab.hasKey(key):
      return shard.tab[key]
    else:
      let value = f(key)
      shard.tab[key] = value
      return value

proc getOrAdd[K, V](
    table: DashTable[K, V], key: sink K, valueToAddOnKeyNotFound: sink V
): V =
  getOrAdd(table, key) do(key: K) -> V:
    valueToAddOnKeyNotFound

proc newDashTable[K, V](shards: int = defaultShards): DashTable[K, V] =
  doAssert shards > 1, "shards must be >1"
  doAssert isPowerOfTwo(shards), "shards must be power of 2"
  DashTable[K, V](shards: newSeqWith(shards, newShard[K, V]()))

# === Cache ===

type CacheLoader = proc(k: string): string {.closure.}

type Cache = ref object
  tab: DashTable[string, LazyValue[string, string]] # store domain/type -> ip/expiredTime
  loader: CacheLoader

proc newCache(loader: CacheLoader): Cache =
  Cache(tab: newDashTable[string, LazyValue[string, string]](), loader: loader)

proc get(cache: Cache, key: string): string =
  let lazyValue = cache.tab.getOrAdd(key) do(k: string) -> LazyValue[string, string]:
    newLazyValue(loader = cache.loader, loaderArg = k)
  lazyValue.get()

proc del(cache: Cache, key: string) =
  cache.tab.del key

# === DoH ===

type Doh* = ref object
  proxy: Proxy
  cache: Cache

let dohUrl = "https://cloudflare-dns.com/dns-query?name=$1&type=$2"

proc resolveViaRemote(doh: Doh, qDomain: string, qType: string): string =
  let url = dohUrl % [qDomain, qType]

  let client = newHttpClient(proxy = doh.proxy)
  defer:
    client.close()

  let response = client.request(
    url = url,
    httpmethod = HttpGet,
    headers = newHttpHeaders({"Accept": "application/dns-json"}),
  )
  let data = response.body()
  info "DoH resolve via remote", qDomain, data

  let jsonObj = parseJson(data)
  let answerList = jsonObj["Answer"]
  let t = if qType == "AAAA": 28 else: 1
  let ipAnswerList = answerList.filterIt(it["type"].getInt == t)
  doAssert ipAnswerList.len != 0

  let firstAnswer = ipAnswerList[0]
  let ip = firstAnswer["data"].getStr
  let exp = getTime().toUnix() + firstAnswer["TTL"].getInt - 10 # expires 10s in advance
  return $ip & "/" & $exp

proc resolveViaCache(doh: Doh, domainAndType: string): string =
  let
    value = doh.cache.get(domainAndType)
    ipAndExp = split(value, "/")
    (ip, exp) = (ipAndExp[0], ipAndExp[1])
  if exp.parseInt() >= getTime().toUnix():
    return ip
  doh.cache.del domainAndType
  debug "DoH resolved via cache failed, maybe expired, try again", domainAndType
  return resolveViaCache(doh, domainAndType)

proc newDoh*(proxyUrl: string): Doh =
  let doh = Doh(proxy: newProxy(url = proxyUrl))
  doh.cache = newCache(
    loader = proc(k: string): string {.closure.} =
      let domainAndType = k.split("/")
      return doh.resolveViaRemote(domainAndType[0], domainAndType[1])
  )
  return doh

proc resolve*(doh: Doh, qDomain: string, qType: string = "A"): string =
  if qDomain in ["cloudflare-dns.com", "one.one.one.one"] and qType == "A":
    return "104.16.249.249"
  return doh.resolveViaCache(qDomain & "/" & qType)
