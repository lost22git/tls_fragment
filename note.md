

| Problem | Resolve |
|----|----|
| DNS hijack | DoH |
| SNI blocking | TLS fragment |



| Website | Requirements |
|------|------|
| common | DoH + TLS fragment |
| cloudflare-dns.com | TCP fragment
| google.com youtube.com ... | not work, maybe IP list resolve via DoH are banned |



TODO:
1. rules: denylist/directlist, doh or not, tls fragment or not
2. no proxy handshake
3. domain fronting

