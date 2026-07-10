# urlscan.io

Publisher: Splunk <br>
Connector Version: 2.6.4 <br>
Product Vendor: urlscan.io <br>
Product Name: urlscan.io <br>
Minimum Product Version: 7.0.0

This app supports investigative actions on urlscan.io

The **api_key** field is not required to use this app, as **urlscan.io** does not require an API key
for querying its database. However, if you wish to start a scan with **detonate url** , then you
will need an API key configured.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Urlscan server. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |

### Configuration variables

This table lists the configuration variables required to operate urlscan.io. These variables are specified when configuring a urlscan.io asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** | optional | password | API key for urlscan.io |
**timeout** | optional | numeric | Timeout period for action (seconds) |
**verify_server_cert** | optional | boolean | Verify server certificate |

### Supported Actions

[test connectivity](#action-test-connectivity) - Test connectivity to urlscan.io and validate the configured API key if present. <br>
[get report](#action-get-report) - Query for results of an already completed detonation <br>
[lookup domain](#action-lookup-domain) - Find information about a domain at urlscan.io <br>
[lookup ip](#action-lookup-ip) - Find information about an IP address at urlscan.io <br>
[detonate url](#action-detonate-url) - Detonate a URL at urlscan.io <br>
[get screenshot](#action-get-screenshot) - Retrieve copy of screenshot file <br>
[make request](#action-make-request) - Execute an arbitrary HTTP request against a urlscan.io API endpoint.

## action: 'test connectivity'

Test connectivity to urlscan.io and validate the configured API key if present.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get report'

Query for results of an already completed detonation

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Detonation ID for the desired report | string | `urlscan submission id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `urlscan submission id` | |
action_result.data.\*.data.console.\*.message.column | numeric | | 1 |
action_result.data.\*.data.console.\*.message.level | string | | info |
action_result.data.\*.data.console.\*.message.line | numeric | | 1 |
action_result.data.\*.data.console.\*.message.source | string | | console-api |
action_result.data.\*.data.console.\*.message.text | string | | message |
action_result.data.\*.data.console.\*.message.timestamp | numeric | | 1721648282157 |
action_result.data.\*.data.console.\*.message.url | string | `url` | https://www.google.com |
action_result.data.\*.data.cookies.\*.domain | string | `domain` | google.com |
action_result.data.\*.data.cookies.\*.expires | numeric | | 1721648282 |
action_result.data.\*.data.cookies.\*.httpOnly | boolean | | True False |
action_result.data.\*.data.cookies.\*.name | string | | session |
action_result.data.\*.data.cookies.\*.partitionKey | string | | https://example.com |
action_result.data.\*.data.cookies.\*.path | string | | / |
action_result.data.\*.data.cookies.\*.priority | string | | Medium |
action_result.data.\*.data.cookies.\*.sameParty | boolean | | True False |
action_result.data.\*.data.cookies.\*.sameSite | string | | Lax |
action_result.data.\*.data.cookies.\*.secure | boolean | | True False |
action_result.data.\*.data.cookies.\*.session | boolean | | True False |
action_result.data.\*.data.cookies.\*.size | numeric | | 64 |
action_result.data.\*.data.cookies.\*.sourcePort | numeric | | 443 |
action_result.data.\*.data.cookies.\*.sourceScheme | string | | Secure |
action_result.data.\*.data.cookies.\*.value | string | | cookie-value |
action_result.data.\*.data.globals.\*.prop | string | | navigator |
action_result.data.\*.data.globals.\*.type | string | | object |
action_result.data.\*.data.links.\*.href | string | `url` | https://www.google.com |
action_result.data.\*.data.links.\*.text | string | | Google |
action_result.data.\*.data.timing.beginNavigation | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.data.timing.domContentEventFired | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.data.timing.frameNavigated | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.data.timing.frameStartedLoading | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.data.timing.frameStoppedLoading | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.data.timing.loadEventFired | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.lists.asns.\* | string | | ['15169'] |
action_result.data.\*.lists.certificates.\*.issuer | string | | WR2 |
action_result.data.\*.lists.certificates.\*.sanList.\* | string | | ['www.google.com'] |
action_result.data.\*.lists.certificates.\*.subjectName | string | | www.google.com |
action_result.data.\*.lists.certificates.\*.validFrom | numeric | | 1719210944 |
action_result.data.\*.lists.certificates.\*.validTo | numeric | | 1726468544 |
action_result.data.\*.lists.countries.\* | string | | ['US'] |
action_result.data.\*.lists.domains.\* | string | | ['google.com'] |
action_result.data.\*.lists.hashes.\* | string | `sha256` | ['d41d8cd98f00b204e9800998ecf8427e'] |
action_result.data.\*.lists.ips.\* | string | | ['8.8.8.8'] |
action_result.data.\*.lists.linkDomains.\* | string | | ['google.com'] |
action_result.data.\*.lists.servers.\* | string | | ['gws'] |
action_result.data.\*.lists.urls.\* | string | `url` | ['https://www.google.com'] |
action_result.data.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.page.asn | string | | AS15169 |
action_result.data.\*.page.asnname | string | | GOOGLE |
action_result.data.\*.page.city | string | | Bursa |
action_result.data.\*.page.country | string | | TR |
action_result.data.\*.page.domain | string | `domain` | yahoo.com |
action_result.data.\*.page.apexDomain | string | | yahoo.com |
action_result.data.\*.page.mimeType | string | | text/html |
action_result.data.\*.page.ptr | string | | dns.google |
action_result.data.\*.page.redirected | string | | sub-domain |
action_result.data.\*.page.server | string | | nginx |
action_result.data.\*.page.status | string | | 200 |
action_result.data.\*.page.title | string | | Yahoo |
action_result.data.\*.page.tlsAgeDays | numeric | | 28 |
action_result.data.\*.page.tlsIssuer | string | | WR2 |
action_result.data.\*.page.tlsValidDays | numeric | | 83 |
action_result.data.\*.page.tlsValidFrom | string | | 2024-06-24T06:35:44.000Z |
action_result.data.\*.page.umbrellaRank | numeric | | 10 |
action_result.data.\*.page.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.scanner.country | string | | us |
action_result.data.\*.stats.requests | numeric | | 69 |
action_result.data.\*.stats.took | numeric | | 25 |
action_result.data.\*.stats.total | numeric | | 1 |
action_result.data.\*.stats.adBlocked | numeric | | 2 |
action_result.data.\*.stats.consoleMsgs | numeric | | 0 |
action_result.data.\*.stats.dataLength | numeric | | 1024 |
action_result.data.\*.stats.domainStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.domainStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.domainStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.domainStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.domainStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.domainStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.domainStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.domainStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.domainStats.\*.compression | string | | gzip |
action_result.data.\*.stats.domainStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.domainStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.domainStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.domainStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.domainStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.domainStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.domainStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.domainStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.domainStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.domainStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.domainStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.domainStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.domainStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.domainStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.domainStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.domainStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.domainStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.domainStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.domainStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.domainStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.domainStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.domainStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.domainStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.domainStats.\*.protocol | string | | https |
action_result.data.\*.stats.domainStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.domainStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.domainStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.domainStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.domainStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.domainStats.\*.securityState | string | | secure |
action_result.data.\*.stats.domainStats.\*.server | string | | nginx |
action_result.data.\*.stats.domainStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.domainStats.\*.type | string | | Document |
action_result.data.\*.stats.encodedDataLength | numeric | | 1024 |
action_result.data.\*.stats.IPv6Percentage | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.ipStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.ipStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.ipStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.ipStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.ipStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.ipStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.ipStats.\*.compression | string | | gzip |
action_result.data.\*.stats.ipStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.ipStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.ipStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.ipStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.ipStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.ipStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.ipStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.ipStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.ipStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.ipStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.ipStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.ipStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.ipStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.ipStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.ipStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.ipStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.ipStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.ipStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.ipStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.ipStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.ipStats.\*.protocol | string | | https |
action_result.data.\*.stats.ipStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.ipStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.ipStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.ipStats.\*.securityState | string | | secure |
action_result.data.\*.stats.ipStats.\*.server | string | | nginx |
action_result.data.\*.stats.ipStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.ipStats.\*.type | string | | Document |
action_result.data.\*.stats.malicious | numeric | | 0 |
action_result.data.\*.stats.protocolStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.protocolStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.protocolStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.protocolStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.protocolStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.protocolStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.protocolStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.protocolStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.protocolStats.\*.compression | string | | gzip |
action_result.data.\*.stats.protocolStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.protocolStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.protocolStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.protocolStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.protocolStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.protocolStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.protocolStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.protocolStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.protocolStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.protocolStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.protocolStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.protocolStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.protocolStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.protocolStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.protocolStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.protocolStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.protocolStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.protocolStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.protocolStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.protocolStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.protocolStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.protocolStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.protocolStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.protocolStats.\*.protocol | string | | https |
action_result.data.\*.stats.protocolStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.protocolStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.protocolStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.protocolStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.protocolStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.protocolStats.\*.securityState | string | | secure |
action_result.data.\*.stats.protocolStats.\*.server | string | | nginx |
action_result.data.\*.stats.protocolStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.protocolStats.\*.type | string | | Document |
action_result.data.\*.stats.regDomainStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.regDomainStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.regDomainStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.regDomainStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.regDomainStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.regDomainStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.regDomainStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.regDomainStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.regDomainStats.\*.compression | string | | gzip |
action_result.data.\*.stats.regDomainStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.regDomainStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.regDomainStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.regDomainStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.regDomainStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.regDomainStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.regDomainStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.regDomainStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.regDomainStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.regDomainStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.regDomainStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.regDomainStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.regDomainStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.regDomainStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.regDomainStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.regDomainStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.regDomainStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.regDomainStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.regDomainStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.regDomainStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.regDomainStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.regDomainStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.regDomainStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.regDomainStats.\*.protocol | string | | https |
action_result.data.\*.stats.regDomainStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.regDomainStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.regDomainStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.regDomainStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.regDomainStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.regDomainStats.\*.securityState | string | | secure |
action_result.data.\*.stats.regDomainStats.\*.server | string | | nginx |
action_result.data.\*.stats.regDomainStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.regDomainStats.\*.type | string | | Document |
action_result.data.\*.stats.resourceStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.resourceStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.resourceStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.resourceStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.resourceStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.resourceStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.resourceStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.resourceStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.resourceStats.\*.compression | string | | gzip |
action_result.data.\*.stats.resourceStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.resourceStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.resourceStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.resourceStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.resourceStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.resourceStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.resourceStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.resourceStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.resourceStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.resourceStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.resourceStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.resourceStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.resourceStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.resourceStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.resourceStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.resourceStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.resourceStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.resourceStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.resourceStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.resourceStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.resourceStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.resourceStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.resourceStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.resourceStats.\*.protocol | string | | https |
action_result.data.\*.stats.resourceStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.resourceStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.resourceStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.resourceStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.resourceStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.resourceStats.\*.securityState | string | | secure |
action_result.data.\*.stats.resourceStats.\*.server | string | | nginx |
action_result.data.\*.stats.resourceStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.resourceStats.\*.type | string | | Document |
action_result.data.\*.stats.securePercentage | numeric | | 100 |
action_result.data.\*.stats.secureRequests | numeric | | 20 |
action_result.data.\*.stats.serverStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.serverStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.serverStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.serverStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.serverStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.serverStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.serverStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.serverStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.serverStats.\*.compression | string | | gzip |
action_result.data.\*.stats.serverStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.serverStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.serverStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.serverStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.serverStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.serverStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.serverStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.serverStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.serverStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.serverStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.serverStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.serverStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.serverStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.serverStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.serverStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.serverStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.serverStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.serverStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.serverStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.serverStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.serverStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.serverStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.serverStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.serverStats.\*.protocol | string | | https |
action_result.data.\*.stats.serverStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.serverStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.serverStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.serverStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.serverStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.serverStats.\*.securityState | string | | secure |
action_result.data.\*.stats.serverStats.\*.server | string | | nginx |
action_result.data.\*.stats.serverStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.serverStats.\*.type | string | | Document |
action_result.data.\*.stats.tlsStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.tlsStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.tlsStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.tlsStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.tlsStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.tlsStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.tlsStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.tlsStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.tlsStats.\*.compression | string | | gzip |
action_result.data.\*.stats.tlsStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.tlsStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.tlsStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.tlsStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.tlsStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.tlsStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.tlsStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.tlsStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.tlsStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.tlsStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.tlsStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.tlsStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.tlsStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.tlsStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.tlsStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.tlsStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.tlsStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.tlsStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.tlsStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.tlsStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.tlsStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.tlsStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.tlsStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.tlsStats.\*.protocol | string | | https |
action_result.data.\*.stats.tlsStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.tlsStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.tlsStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.tlsStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.tlsStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.tlsStats.\*.securityState | string | | secure |
action_result.data.\*.stats.tlsStats.\*.server | string | | nginx |
action_result.data.\*.stats.tlsStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.tlsStats.\*.type | string | | Document |
action_result.data.\*.stats.totalLinks | numeric | | 10 |
action_result.data.\*.stats.uniqCountries | numeric | | 1 |
action_result.data.\*.stats.uniqIPs | numeric | | 1 |
action_result.data.\*.submitter.country | string | | us |
action_result.data.\*.task.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.task.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.task.domURL | string | `url` | http://test.test |
action_result.data.\*.task.domain | string | | yahoo.com |
action_result.data.\*.task.apexDomain | string | | yahoo.com |
action_result.data.\*.task.method | string | | GET |
action_result.data.\*.task.options.useragent | string | | TestBrowser/7.0 |
action_result.data.\*.task.reportURL | string | `url` | https://urlscan.io/result/f04f2a29-d455-4830-874a-88191fb79352/ |
action_result.data.\*.task.screenshotURL | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.task.source | string | | 4b0fb6d4 |
action_result.data.\*.task.time | string | | 2017-08-07T19:13:17.870Z |
action_result.data.\*.task.userAgent | string | | TestBrowser/7.0 |
action_result.data.\*.task.visibility | string | | public |
action_result.data.\*.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.verdicts.community.hasVerdicts | boolean | | True False |
action_result.data.\*.verdicts.community.malicious | boolean | | True False |
action_result.data.\*.verdicts.community.score | numeric | | 0 |
action_result.data.\*.verdicts.community.votesBenign | numeric | | 0 |
action_result.data.\*.verdicts.community.votesMalicious | numeric | | 0 |
action_result.data.\*.verdicts.community.votesTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.benignTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.enginesTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.malicious | boolean | | True False |
action_result.data.\*.verdicts.engines.maliciousTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.score | numeric | | 0 |
action_result.data.\*.verdicts.overall.hasVerdicts | boolean | | True False |
action_result.data.\*.verdicts.overall.malicious | boolean | | True False |
action_result.data.\*.verdicts.overall.score | numeric | | 0 |
action_result.data.\*.verdicts.urlscan.hasVerdicts | boolean | | True False |
action_result.data.\*.verdicts.urlscan.malicious | boolean | | True False |
action_result.data.\*.verdicts.urlscan.score | numeric | | 0 |
action_result.data.\*.visibility | string | | public |
action_result.summary.report_uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.summary.scan_uuid | string | | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.summary.page_domain | string | | yahoo.com |
action_result.summary.added_tags_num | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup domain'

Find information about a domain at urlscan.io

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to lookup | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.domain | string | `domain` | |
action_result.data.\*.has_more | boolean | | True False |
action_result.data.\*.results.\*.\_id | string | | 86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.results.\*.indexedAt | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.results.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.page.asn | string | | AS15169 |
action_result.data.\*.results.\*.page.asnname | string | | GOOGLE |
action_result.data.\*.results.\*.page.city | string | | Bursa |
action_result.data.\*.results.\*.page.country | string | | TR |
action_result.data.\*.results.\*.page.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.page.apexDomain | string | | yahoo.com |
action_result.data.\*.results.\*.page.mimeType | string | | text/html |
action_result.data.\*.results.\*.page.ptr | string | | dns.google |
action_result.data.\*.results.\*.page.redirected | string | | sub-domain |
action_result.data.\*.results.\*.page.server | string | | nginx |
action_result.data.\*.results.\*.page.status | string | | 200 |
action_result.data.\*.results.\*.page.title | string | | Yahoo |
action_result.data.\*.results.\*.page.tlsAgeDays | numeric | | 28 |
action_result.data.\*.results.\*.page.tlsIssuer | string | | WR2 |
action_result.data.\*.results.\*.page.tlsValidDays | numeric | | 83 |
action_result.data.\*.results.\*.page.tlsValidFrom | string | | 2024-06-24T06:35:44.000Z |
action_result.data.\*.results.\*.page.umbrellaRank | numeric | | 10 |
action_result.data.\*.results.\*.page.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.results.\*.task.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.results.\*.task.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.results.\*.task.domURL | string | `url` | http://test.test |
action_result.data.\*.results.\*.task.domain | string | | yahoo.com |
action_result.data.\*.results.\*.task.apexDomain | string | | yahoo.com |
action_result.data.\*.results.\*.task.method | string | | GET |
action_result.data.\*.results.\*.task.options.useragent | string | | TestBrowser/7.0 |
action_result.data.\*.results.\*.task.reportURL | string | `url` | https://urlscan.io/result/f04f2a29-d455-4830-874a-88191fb79352/ |
action_result.data.\*.results.\*.task.screenshotURL | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.results.\*.task.source | string | | 4b0fb6d4 |
action_result.data.\*.results.\*.task.time | string | | 2017-08-07T19:13:17.870Z |
action_result.data.\*.results.\*.task.userAgent | string | | TestBrowser/7.0 |
action_result.data.\*.results.\*.task.visibility | string | | public |
action_result.data.\*.results.\*.result | string | `url` | https://urlscan.io/api/v1/result/86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.results.\*.screenshot | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.results.\*.sort.\* | string | | ['2024-07-22T10:18:02.157Z', '86b7f70a-5039-419f-9aeb-8cba09404e92'] |
action_result.data.\*.results.\*.stats.requests | numeric | | 69 |
action_result.data.\*.results.\*.stats.took | numeric | | 25 |
action_result.data.\*.results.\*.stats.total | numeric | | 1 |
action_result.data.\*.results.\*.stats.adBlocked | numeric | | 2 |
action_result.data.\*.results.\*.stats.consoleMsgs | numeric | | 0 |
action_result.data.\*.results.\*.stats.dataLength | numeric | | 1024 |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.domainStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.domainStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.domainStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.domainStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.domainStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.domainStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.domainStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.domainStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.domainStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.domainStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.domainStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.domainStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.domainStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.domainStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.domainStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.domainStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.domainStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.domainStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.domainStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.domainStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.domainStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.domainStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.encodedDataLength | numeric | | 1024 |
action_result.data.\*.results.\*.stats.IPv6Percentage | numeric | | 0 |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.ipStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.ipStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.ipStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.ipStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.ipStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.ipStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.ipStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.ipStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.ipStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.ipStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.ipStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.ipStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.ipStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.ipStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.ipStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.ipStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.ipStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.ipStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.ipStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.ipStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.ipStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.ipStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.malicious | numeric | | 0 |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.protocolStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.protocolStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.protocolStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.protocolStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.protocolStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.protocolStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.protocolStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.protocolStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.protocolStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.protocolStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.protocolStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.protocolStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.protocolStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.protocolStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.protocolStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.protocolStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.protocolStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.protocolStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.protocolStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.protocolStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.protocolStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.regDomainStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.regDomainStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.regDomainStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.regDomainStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.regDomainStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.regDomainStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.regDomainStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.regDomainStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.regDomainStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.regDomainStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.regDomainStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.resourceStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.resourceStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.resourceStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.resourceStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.resourceStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.resourceStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.resourceStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.resourceStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.resourceStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.resourceStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.resourceStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.resourceStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.resourceStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.resourceStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.resourceStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.resourceStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.resourceStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.resourceStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.resourceStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.resourceStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.resourceStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.securePercentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.secureRequests | numeric | | 20 |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.serverStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.serverStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.serverStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.serverStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.serverStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.serverStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.serverStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.serverStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.serverStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.serverStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.serverStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.serverStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.serverStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.serverStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.serverStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.serverStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.serverStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.serverStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.serverStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.serverStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.serverStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.serverStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.tlsStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.tlsStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.tlsStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.tlsStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.tlsStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.tlsStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.tlsStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.tlsStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.tlsStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.tlsStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.tlsStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.tlsStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.tlsStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.tlsStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.tlsStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.tlsStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.tlsStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.tlsStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.tlsStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.tlsStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.tlsStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.totalLinks | numeric | | 10 |
action_result.data.\*.results.\*.stats.uniqCountries | numeric | | 1 |
action_result.data.\*.results.\*.stats.uniqIPs | numeric | | 1 |
action_result.data.\*.results.\*.uniq_countries | numeric | | 1 |
action_result.data.\*.took | numeric | | 25 |
action_result.data.\*.total | numeric | | 1 |
action_result.summary.total | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup ip'

Find information about an IP address at urlscan.io

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to lookup | string | `ip` `ipv6` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.data.\*.has_more | boolean | | True False |
action_result.data.\*.results.\*.\_id | string | | 86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.results.\*.indexedAt | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.results.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.page.asn | string | | AS15169 |
action_result.data.\*.results.\*.page.asnname | string | | GOOGLE |
action_result.data.\*.results.\*.page.city | string | | Bursa |
action_result.data.\*.results.\*.page.country | string | | TR |
action_result.data.\*.results.\*.page.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.page.apexDomain | string | | yahoo.com |
action_result.data.\*.results.\*.page.mimeType | string | | text/html |
action_result.data.\*.results.\*.page.ptr | string | | dns.google |
action_result.data.\*.results.\*.page.redirected | string | | sub-domain |
action_result.data.\*.results.\*.page.server | string | | nginx |
action_result.data.\*.results.\*.page.status | string | | 200 |
action_result.data.\*.results.\*.page.title | string | | Yahoo |
action_result.data.\*.results.\*.page.tlsAgeDays | numeric | | 28 |
action_result.data.\*.results.\*.page.tlsIssuer | string | | WR2 |
action_result.data.\*.results.\*.page.tlsValidDays | numeric | | 83 |
action_result.data.\*.results.\*.page.tlsValidFrom | string | | 2024-06-24T06:35:44.000Z |
action_result.data.\*.results.\*.page.umbrellaRank | numeric | | 10 |
action_result.data.\*.results.\*.page.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.results.\*.task.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.results.\*.task.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.results.\*.task.domURL | string | `url` | http://test.test |
action_result.data.\*.results.\*.task.domain | string | | yahoo.com |
action_result.data.\*.results.\*.task.apexDomain | string | | yahoo.com |
action_result.data.\*.results.\*.task.method | string | | GET |
action_result.data.\*.results.\*.task.options.useragent | string | | TestBrowser/7.0 |
action_result.data.\*.results.\*.task.reportURL | string | `url` | https://urlscan.io/result/f04f2a29-d455-4830-874a-88191fb79352/ |
action_result.data.\*.results.\*.task.screenshotURL | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.results.\*.task.source | string | | 4b0fb6d4 |
action_result.data.\*.results.\*.task.time | string | | 2017-08-07T19:13:17.870Z |
action_result.data.\*.results.\*.task.userAgent | string | | TestBrowser/7.0 |
action_result.data.\*.results.\*.task.visibility | string | | public |
action_result.data.\*.results.\*.result | string | `url` | https://urlscan.io/api/v1/result/86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.results.\*.screenshot | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.results.\*.sort.\* | string | | ['2024-07-22T10:18:02.157Z', '86b7f70a-5039-419f-9aeb-8cba09404e92'] |
action_result.data.\*.results.\*.stats.requests | numeric | | 69 |
action_result.data.\*.results.\*.stats.took | numeric | | 25 |
action_result.data.\*.results.\*.stats.total | numeric | | 1 |
action_result.data.\*.results.\*.stats.adBlocked | numeric | | 2 |
action_result.data.\*.results.\*.stats.consoleMsgs | numeric | | 0 |
action_result.data.\*.results.\*.stats.dataLength | numeric | | 1024 |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.domainStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.domainStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.domainStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.domainStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.domainStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.domainStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.domainStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.domainStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.domainStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.domainStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.domainStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.domainStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.domainStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.domainStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.domainStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.domainStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.domainStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.domainStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.domainStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.domainStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.domainStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.domainStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.domainStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.domainStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.domainStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.encodedDataLength | numeric | | 1024 |
action_result.data.\*.results.\*.stats.IPv6Percentage | numeric | | 0 |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.ipStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.ipStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.ipStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.ipStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.ipStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.ipStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.ipStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.ipStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.ipStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.ipStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.ipStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.ipStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.ipStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.ipStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.ipStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.ipStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.ipStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.ipStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.ipStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.ipStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.ipStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.ipStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.ipStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.ipStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.ipStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.malicious | numeric | | 0 |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.protocolStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.protocolStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.protocolStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.protocolStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.protocolStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.protocolStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.protocolStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.protocolStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.protocolStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.protocolStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.protocolStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.protocolStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.protocolStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.protocolStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.protocolStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.protocolStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.protocolStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.protocolStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.protocolStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.protocolStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.protocolStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.protocolStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.protocolStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.protocolStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.regDomainStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.regDomainStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.regDomainStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.regDomainStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.regDomainStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.regDomainStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.regDomainStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.regDomainStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.regDomainStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.regDomainStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.regDomainStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.regDomainStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.regDomainStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.regDomainStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.regDomainStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.resourceStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.resourceStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.resourceStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.resourceStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.resourceStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.resourceStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.resourceStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.resourceStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.resourceStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.resourceStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.resourceStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.resourceStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.resourceStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.resourceStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.resourceStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.resourceStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.resourceStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.resourceStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.resourceStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.resourceStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.resourceStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.resourceStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.resourceStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.resourceStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.securePercentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.secureRequests | numeric | | 20 |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.serverStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.serverStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.serverStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.serverStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.serverStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.serverStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.serverStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.serverStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.serverStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.serverStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.serverStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.serverStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.serverStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.serverStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.serverStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.serverStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.serverStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.serverStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.serverStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.serverStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.serverStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.serverStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.serverStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.serverStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.serverStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.country | string | | TR |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.name | string | | DGN |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.results.\*.stats.tlsStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.results.\*.stats.tlsStats.\*.compression | string | | gzip |
action_result.data.\*.results.\*.stats.tlsStats.\*.count | numeric | | 1 |
action_result.data.\*.results.\*.stats.tlsStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.results.\*.stats.tlsStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.tlsStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.results.\*.stats.tlsStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.country | string | | TR |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.region | string | | 16 |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.results.\*.stats.tlsStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.results.\*.stats.tlsStats.\*.index | numeric | | 0 |
action_result.data.\*.results.\*.stats.tlsStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.results.\*.stats.tlsStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.tlsStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.results.\*.stats.tlsStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.results.\*.stats.tlsStats.\*.latency | numeric | | 25 |
action_result.data.\*.results.\*.stats.tlsStats.\*.percentage | numeric | | 100 |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocol | string | | https |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.\* | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.results.\*.stats.tlsStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.stats.tlsStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.results.\*.stats.tlsStats.\*.redirects | numeric | | 0 |
action_result.data.\*.results.\*.stats.tlsStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.stats.tlsStats.\*.requests | numeric | | 1 |
action_result.data.\*.results.\*.stats.tlsStats.\*.securityState | string | | secure |
action_result.data.\*.results.\*.stats.tlsStats.\*.server | string | | nginx |
action_result.data.\*.results.\*.stats.tlsStats.\*.size | numeric | | 1234 |
action_result.data.\*.results.\*.stats.tlsStats.\*.type | string | | Document |
action_result.data.\*.results.\*.stats.totalLinks | numeric | | 10 |
action_result.data.\*.results.\*.stats.uniqCountries | numeric | | 1 |
action_result.data.\*.results.\*.stats.uniqIPs | numeric | | 1 |
action_result.data.\*.results.\*.uniq_countries | numeric | | 1 |
action_result.data.\*.took | numeric | | 25 |
action_result.data.\*.total | numeric | | 1 |
action_result.summary.total | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate url'

Detonate a URL at urlscan.io

Type: **investigate** <br>
Read only: **False**

If the get_result parameter is set to true, then the action may take up to 2-3 minutes to execute because the action will poll for the results in the same call.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to detonate | string | `url` `domain` |
**tags** | optional | Comma-separated list of tags to annotate this scan. Limited to 10 tags. Tags with lengths longer than 29 will be omitted | string | |
**private** | optional | Run a private scan | boolean | |
**custom_agent** | optional | Override User-Agent for this scan | string | |
**get_result** | optional | Get scan result in same call | boolean | |
**addto_vault** | optional | Add url screenshot to vault | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` `domain` | |
action_result.parameter.tags | string | | |
action_result.parameter.private | boolean | | |
action_result.parameter.custom_agent | string | | |
action_result.parameter.get_result | boolean | | |
action_result.parameter.addto_vault | boolean | | |
action_result.data.\*.data.console.\*.message.column | numeric | | 1 |
action_result.data.\*.data.console.\*.message.level | string | | info |
action_result.data.\*.data.console.\*.message.line | numeric | | 1 |
action_result.data.\*.data.console.\*.message.source | string | | console-api |
action_result.data.\*.data.console.\*.message.text | string | | message |
action_result.data.\*.data.console.\*.message.timestamp | numeric | | 1721648282157 |
action_result.data.\*.data.console.\*.message.url | string | `url` | https://www.google.com |
action_result.data.\*.data.cookies.\*.domain | string | `domain` | google.com |
action_result.data.\*.data.cookies.\*.expires | numeric | | 1721648282 |
action_result.data.\*.data.cookies.\*.httpOnly | boolean | | True False |
action_result.data.\*.data.cookies.\*.name | string | | session |
action_result.data.\*.data.cookies.\*.partitionKey | string | | https://example.com |
action_result.data.\*.data.cookies.\*.path | string | | / |
action_result.data.\*.data.cookies.\*.priority | string | | Medium |
action_result.data.\*.data.cookies.\*.sameParty | boolean | | True False |
action_result.data.\*.data.cookies.\*.sameSite | string | | Lax |
action_result.data.\*.data.cookies.\*.secure | boolean | | True False |
action_result.data.\*.data.cookies.\*.session | boolean | | True False |
action_result.data.\*.data.cookies.\*.size | numeric | | 64 |
action_result.data.\*.data.cookies.\*.sourcePort | numeric | | 443 |
action_result.data.\*.data.cookies.\*.sourceScheme | string | | Secure |
action_result.data.\*.data.cookies.\*.value | string | | cookie-value |
action_result.data.\*.data.globals.\*.prop | string | | navigator |
action_result.data.\*.data.globals.\*.type | string | | object |
action_result.data.\*.data.links.\*.href | string | `url` | https://www.google.com |
action_result.data.\*.data.links.\*.text | string | | Google |
action_result.data.\*.data.timing.beginNavigation | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.data.timing.domContentEventFired | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.data.timing.frameNavigated | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.data.timing.frameStartedLoading | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.data.timing.frameStoppedLoading | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.data.timing.loadEventFired | string | | 2024-07-22T10:18:02.157Z |
action_result.data.\*.lists.asns.\* | string | | ['15169'] |
action_result.data.\*.lists.certificates.\*.issuer | string | | WR2 |
action_result.data.\*.lists.certificates.\*.sanList.\* | string | | ['www.google.com'] |
action_result.data.\*.lists.certificates.\*.subjectName | string | | www.google.com |
action_result.data.\*.lists.certificates.\*.validFrom | numeric | | 1719210944 |
action_result.data.\*.lists.certificates.\*.validTo | numeric | | 1726468544 |
action_result.data.\*.lists.countries.\* | string | | ['US'] |
action_result.data.\*.lists.domains.\* | string | | ['google.com'] |
action_result.data.\*.lists.hashes.\* | string | `sha256` | ['d41d8cd98f00b204e9800998ecf8427e'] |
action_result.data.\*.lists.ips.\* | string | | ['8.8.8.8'] |
action_result.data.\*.lists.linkDomains.\* | string | | ['google.com'] |
action_result.data.\*.lists.servers.\* | string | | ['gws'] |
action_result.data.\*.lists.urls.\* | string | `url` | ['https://www.google.com'] |
action_result.data.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.page.asn | string | | AS15169 |
action_result.data.\*.page.asnname | string | | GOOGLE |
action_result.data.\*.page.city | string | | Bursa |
action_result.data.\*.page.country | string | | TR |
action_result.data.\*.page.domain | string | `domain` | yahoo.com |
action_result.data.\*.page.apexDomain | string | | yahoo.com |
action_result.data.\*.page.mimeType | string | | text/html |
action_result.data.\*.page.ptr | string | | dns.google |
action_result.data.\*.page.redirected | string | | sub-domain |
action_result.data.\*.page.server | string | | nginx |
action_result.data.\*.page.status | string | | 200 |
action_result.data.\*.page.title | string | | Yahoo |
action_result.data.\*.page.tlsAgeDays | numeric | | 28 |
action_result.data.\*.page.tlsIssuer | string | | WR2 |
action_result.data.\*.page.tlsValidDays | numeric | | 83 |
action_result.data.\*.page.tlsValidFrom | string | | 2024-06-24T06:35:44.000Z |
action_result.data.\*.page.umbrellaRank | numeric | | 10 |
action_result.data.\*.page.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.scanner.country | string | | us |
action_result.data.\*.stats.requests | numeric | | 69 |
action_result.data.\*.stats.took | numeric | | 25 |
action_result.data.\*.stats.total | numeric | | 1 |
action_result.data.\*.stats.adBlocked | numeric | | 2 |
action_result.data.\*.stats.consoleMsgs | numeric | | 0 |
action_result.data.\*.stats.dataLength | numeric | | 1024 |
action_result.data.\*.stats.domainStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.domainStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.domainStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.domainStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.domainStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.domainStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.domainStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.domainStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.domainStats.\*.compression | string | | gzip |
action_result.data.\*.stats.domainStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.domainStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.domainStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.domainStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.domainStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.domainStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.domainStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.domainStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.domainStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.domainStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.domainStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.domainStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.domainStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.domainStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.domainStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.domainStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.domainStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.domainStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.domainStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.domainStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.domainStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.domainStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.domainStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.domainStats.\*.protocol | string | | https |
action_result.data.\*.stats.domainStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.domainStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.domainStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.domainStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.domainStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.domainStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.domainStats.\*.securityState | string | | secure |
action_result.data.\*.stats.domainStats.\*.server | string | | nginx |
action_result.data.\*.stats.domainStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.domainStats.\*.type | string | | Document |
action_result.data.\*.stats.encodedDataLength | numeric | | 1024 |
action_result.data.\*.stats.IPv6Percentage | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.ipStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.ipStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.ipStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.ipStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.ipStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.ipStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.ipStats.\*.compression | string | | gzip |
action_result.data.\*.stats.ipStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.ipStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.ipStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.ipStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.ipStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.ipStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.ipStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.ipStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.ipStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.ipStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.ipStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.ipStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.ipStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.ipStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.ipStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.ipStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.ipStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.ipStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.ipStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.ipStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.ipStats.\*.protocol | string | | https |
action_result.data.\*.stats.ipStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.ipStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.ipStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.ipStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.ipStats.\*.securityState | string | | secure |
action_result.data.\*.stats.ipStats.\*.server | string | | nginx |
action_result.data.\*.stats.ipStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.ipStats.\*.type | string | | Document |
action_result.data.\*.stats.malicious | numeric | | 0 |
action_result.data.\*.stats.protocolStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.protocolStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.protocolStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.protocolStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.protocolStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.protocolStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.protocolStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.protocolStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.protocolStats.\*.compression | string | | gzip |
action_result.data.\*.stats.protocolStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.protocolStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.protocolStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.protocolStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.protocolStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.protocolStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.protocolStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.protocolStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.protocolStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.protocolStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.protocolStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.protocolStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.protocolStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.protocolStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.protocolStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.protocolStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.protocolStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.protocolStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.protocolStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.protocolStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.protocolStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.protocolStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.protocolStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.protocolStats.\*.protocol | string | | https |
action_result.data.\*.stats.protocolStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.protocolStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.protocolStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.protocolStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.protocolStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.protocolStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.protocolStats.\*.securityState | string | | secure |
action_result.data.\*.stats.protocolStats.\*.server | string | | nginx |
action_result.data.\*.stats.protocolStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.protocolStats.\*.type | string | | Document |
action_result.data.\*.stats.regDomainStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.regDomainStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.regDomainStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.regDomainStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.regDomainStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.regDomainStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.regDomainStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.regDomainStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.regDomainStats.\*.compression | string | | gzip |
action_result.data.\*.stats.regDomainStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.regDomainStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.regDomainStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.regDomainStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.regDomainStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.regDomainStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.regDomainStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.regDomainStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.regDomainStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.regDomainStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.regDomainStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.regDomainStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.regDomainStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.regDomainStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.regDomainStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.regDomainStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.regDomainStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.regDomainStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.regDomainStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.regDomainStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.regDomainStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.regDomainStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.regDomainStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.regDomainStats.\*.protocol | string | | https |
action_result.data.\*.stats.regDomainStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.regDomainStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.regDomainStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.regDomainStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.regDomainStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.regDomainStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.regDomainStats.\*.securityState | string | | secure |
action_result.data.\*.stats.regDomainStats.\*.server | string | | nginx |
action_result.data.\*.stats.regDomainStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.regDomainStats.\*.type | string | | Document |
action_result.data.\*.stats.resourceStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.resourceStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.resourceStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.resourceStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.resourceStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.resourceStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.resourceStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.resourceStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.resourceStats.\*.compression | string | | gzip |
action_result.data.\*.stats.resourceStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.resourceStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.resourceStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.resourceStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.resourceStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.resourceStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.resourceStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.resourceStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.resourceStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.resourceStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.resourceStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.resourceStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.resourceStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.resourceStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.resourceStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.resourceStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.resourceStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.resourceStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.resourceStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.resourceStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.resourceStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.resourceStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.resourceStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.resourceStats.\*.protocol | string | | https |
action_result.data.\*.stats.resourceStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.resourceStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.resourceStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.resourceStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.resourceStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.resourceStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.resourceStats.\*.securityState | string | | secure |
action_result.data.\*.stats.resourceStats.\*.server | string | | nginx |
action_result.data.\*.stats.resourceStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.resourceStats.\*.type | string | | Document |
action_result.data.\*.stats.securePercentage | numeric | | 100 |
action_result.data.\*.stats.secureRequests | numeric | | 20 |
action_result.data.\*.stats.serverStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.serverStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.serverStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.serverStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.serverStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.serverStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.serverStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.serverStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.serverStats.\*.compression | string | | gzip |
action_result.data.\*.stats.serverStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.serverStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.serverStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.serverStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.serverStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.serverStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.serverStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.serverStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.serverStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.serverStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.serverStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.serverStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.serverStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.serverStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.serverStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.serverStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.serverStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.serverStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.serverStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.serverStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.serverStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.serverStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.serverStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.serverStats.\*.protocol | string | | https |
action_result.data.\*.stats.serverStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.serverStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.serverStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.serverStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.serverStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.serverStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.serverStats.\*.securityState | string | | secure |
action_result.data.\*.stats.serverStats.\*.server | string | | nginx |
action_result.data.\*.stats.serverStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.serverStats.\*.type | string | | Document |
action_result.data.\*.stats.tlsStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.tlsStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.tlsStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.tlsStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.tlsStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.tlsStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.tlsStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.tlsStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.tlsStats.\*.compression | string | | gzip |
action_result.data.\*.stats.tlsStats.\*.count | numeric | | 1 |
action_result.data.\*.stats.tlsStats.\*.countries.\* | string | | ['US'] |
action_result.data.\*.stats.tlsStats.\*.domain | string | `domain` | yahoo.com |
action_result.data.\*.stats.tlsStats.\*.domains.\* | string | | ['yahoo.com'] |
action_result.data.\*.stats.tlsStats.\*.encodedSize | numeric | | 1234 |
action_result.data.\*.stats.tlsStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.tlsStats.\*.geoip.city | string | | Bursa |
action_result.data.\*.stats.tlsStats.\*.geoip.country | string | | TR |
action_result.data.\*.stats.tlsStats.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.stats.tlsStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.tlsStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.tlsStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.tlsStats.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.stats.tlsStats.\*.geoip.region | string | | 16 |
action_result.data.\*.stats.tlsStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.tlsStats.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.stats.tlsStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.tlsStats.\*.initiators.\* | string | | ['redirect'] |
action_result.data.\*.stats.tlsStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.tlsStats.\*.ips.\* | string | `ip` `ipv6` | ['8.8.8.8'] |
action_result.data.\*.stats.tlsStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.tlsStats.\*.latency | numeric | | 25 |
action_result.data.\*.stats.tlsStats.\*.percentage | numeric | | 100 |
action_result.data.\*.stats.tlsStats.\*.protocol | string | | https |
action_result.data.\*.stats.tlsStats.\*.protocols.\* | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.3 / NONE / AES_128_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | |
action_result.data.\*.stats.tlsStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.tlsStats.\*.rdns.ptr | string | | dns.google |
action_result.data.\*.stats.tlsStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.tlsStats.\*.regDomain | string | `domain` | yahoo.com |
action_result.data.\*.stats.tlsStats.\*.requests | numeric | | 1 |
action_result.data.\*.stats.tlsStats.\*.securityState | string | | secure |
action_result.data.\*.stats.tlsStats.\*.server | string | | nginx |
action_result.data.\*.stats.tlsStats.\*.size | numeric | | 1234 |
action_result.data.\*.stats.tlsStats.\*.type | string | | Document |
action_result.data.\*.stats.totalLinks | numeric | | 10 |
action_result.data.\*.stats.uniqCountries | numeric | | 1 |
action_result.data.\*.stats.uniqIPs | numeric | | 1 |
action_result.data.\*.submitter.country | string | | us |
action_result.data.\*.task.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.task.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.task.domURL | string | `url` | http://test.test |
action_result.data.\*.task.domain | string | | yahoo.com |
action_result.data.\*.task.apexDomain | string | | yahoo.com |
action_result.data.\*.task.method | string | | GET |
action_result.data.\*.task.options.useragent | string | | TestBrowser/7.0 |
action_result.data.\*.task.reportURL | string | `url` | https://urlscan.io/result/f04f2a29-d455-4830-874a-88191fb79352/ |
action_result.data.\*.task.screenshotURL | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.task.source | string | | 4b0fb6d4 |
action_result.data.\*.task.time | string | | 2017-08-07T19:13:17.870Z |
action_result.data.\*.task.userAgent | string | | TestBrowser/7.0 |
action_result.data.\*.task.visibility | string | | public |
action_result.data.\*.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.verdicts.community.hasVerdicts | boolean | | True False |
action_result.data.\*.verdicts.community.malicious | boolean | | True False |
action_result.data.\*.verdicts.community.score | numeric | | 0 |
action_result.data.\*.verdicts.community.votesBenign | numeric | | 0 |
action_result.data.\*.verdicts.community.votesMalicious | numeric | | 0 |
action_result.data.\*.verdicts.community.votesTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.benignTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.enginesTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.malicious | boolean | | True False |
action_result.data.\*.verdicts.engines.maliciousTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.score | numeric | | 0 |
action_result.data.\*.verdicts.overall.hasVerdicts | boolean | | True False |
action_result.data.\*.verdicts.overall.malicious | boolean | | True False |
action_result.data.\*.verdicts.overall.score | numeric | | 0 |
action_result.data.\*.verdicts.urlscan.hasVerdicts | boolean | | True False |
action_result.data.\*.verdicts.urlscan.malicious | boolean | | True False |
action_result.data.\*.verdicts.urlscan.score | numeric | | 0 |
action_result.data.\*.visibility | string | | public |
action_result.data.\*.api | string | `url` | https://urlscan.io/api/v1/result/f04f2a29-d455-4830-874a-88191fb79352/ |
action_result.data.\*.message | string | | Submission successful |
action_result.data.\*.description | string | | The submitted URL was blocked from scanning. |
action_result.data.\*.fieldErrors.\*.location | string | | body |
action_result.data.\*.fieldErrors.\*.msg | string | | must be between 5 and 2083 characters |
action_result.data.\*.fieldErrors.\*.param | string | | url |
action_result.data.\*.fieldErrors.\*.value | string | | 123 |
action_result.data.\*.options.useragent | string | | TestBrowser/7.0 |
action_result.data.\*.result | string | `url` | https://urlscan.io/api/v1/result/f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.status | numeric | | 400 |
action_result.data.\*.requested_url | string | `url` | https://www.yahoo.com |
action_result.data.\*.requested_get_result | boolean | | True False |
action_result.data.\*.submitted_tags.\* | string | | ['test_tag1', 'test_tag2'] |
action_result.data.\*.omitted_tags.\* | string | | ['this_tag_is_longer_than_twenty_nine_chars'] |
action_result.data.\*.omitted_tags_num | numeric | | 1 |
action_result.summary.added_tags_num | numeric | | 1 |
action_result.summary.omitted_tags_num | numeric | | 1 |
action_result.summary.vault_id | string | | 0599692c5298dd88f731960c55299f8de3331cf1 |
action_result.summary.name | string | | cf9412df-963e-46a2-849b-de693d055b7b.png |
action_result.summary.file_type | string | | image/png |
action_result.summary.id | numeric | | 722 |
action_result.summary.container_id | numeric | | 2390 |
action_result.summary.size | numeric | | 13841 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get screenshot'

Retrieve copy of screenshot file

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** | required | UUID of report | string | `urlscan submission id` |
**container_id** | optional | Event to add file to, will default to current container id | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.report_id | string | `urlscan submission id` | |
action_result.parameter.container_id | numeric | | |
action_result.data.\*.report_id | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.vault_id | string | | 0599692c5298dd88f731960c55299f8de3331cf1 |
action_result.data.\*.name | string | | cf9412df-963e-46a2-849b-de693d055b7b.png |
action_result.data.\*.file_type | string | | image/png |
action_result.data.\*.id | numeric | | 722 |
action_result.data.\*.container_id | numeric | | 2390 |
action_result.data.\*.size | numeric | | 13841 |
action_result.summary.id | numeric | | 722 |
action_result.summary.name | string | | cf9412df-963e-46a2-849b-de693d055b7b.png |
action_result.summary.size | numeric | | 13841 |
action_result.summary.vault_id | string | | 0599692c5298dd88f731960c55299f8de3331cf1 |
action_result.summary.file_type | string | | image/png |
action_result.summary.container_id | numeric | | 2390 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

Execute an arbitrary HTTP request against a urlscan.io API endpoint.

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | urlscan.io endpoint path, relative to https://urlscan.io. For example: 'api/v1/search/?q=domain:example.com' or 'api/v1/result/{uuid}'. | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is False. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"key": "value"} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
