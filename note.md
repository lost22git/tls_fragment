

| Problem | Resolve |
|----|----|
| DNS hijack | DoH |
| SNI blocking | TLS fragment |



| Website | Requirements |
|------|------|
| common | DoH + TLS fragment |
| cloudflare-dns.com | DoH + TLS fragment + TCP fragment
| google.com youtube.com ... | **not work**, maybe IP list resolved via DoH are banned |



TODO:
1. rules: denylist/directlist, doh or not, tls fragment or not
2. domain fronting

