



| Problem | Resolve |
|----|----|
| DNS hijack | DoH |
| SNI blocking | TLS fragmentize & TCP fragmentize |





| Website | Requirements |
|------|------|
| common | DoH + TLS fragmentize |
| cloudflare-dns.com | TCP fragmentize |
| google.com youtube.com ... | not work, maybe IP list resolve via DoH are banned |

