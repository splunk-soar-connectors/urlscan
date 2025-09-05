# urlscan.io

Publisher: Splunk <br>
Connector Version: 2.6.3 <br>
Product Vendor: urlscan.io <br>
Product Name: urlscan.io <br>
Minimum Product Version: 6.2.1

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

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration <br>
[get report](#action-get-report) - Query for results of an already completed detonation <br>
[lookup domain](#action-lookup-domain) - Find information about a domain at urlscan.io <br>
[lookup ip](#action-lookup-ip) - Find information about an IP address at urlscan.io <br>
[detonate url](#action-detonate-url) - Detonate a URL at urlscan.io <br>
[get screenshot](#action-get-screenshot) - Retrieve copy of screenshot file

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** <br>
Read only: **True**

This will attempt to connect by running an action which would require usage of the API key. If there is no API key set, it will still run a query to make sure the <b>urlscan.io</b> API can be queried.

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

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
action_result.status | string | | success failed |
action_result.parameter.id | string | `urlscan submission id` | test-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.data.console.\*.message.column | numeric | | 552 |
action_result.data.\*.data.console.\*.message.level | string | | log |
action_result.data.\*.data.console.\*.message.line | numeric | | 2 |
action_result.data.\*.data.console.\*.message.source | string | | console-api |
action_result.data.\*.data.console.\*.message.text | string | | JQMIGRATE: Migrate is installed, version 1.4.1 |
action_result.data.\*.data.console.\*.message.url | string | `url` | https://test.test |
action_result.data.\*.data.cookies.\*.domain | string | `domain` | .test.test |
action_result.data.\*.data.cookies.\*.expires | numeric | | 1620630019.555948 |
action_result.data.\*.data.cookies.\*.httpOnly | boolean | | False |
action_result.data.\*.data.cookies.\*.name | string | | TestName |
action_result.data.\*.data.cookies.\*.path | string | | / |
action_result.data.\*.data.cookies.\*.priority | string | | Medium |
action_result.data.\*.data.cookies.\*.sameParty | boolean | | False |
action_result.data.\*.data.cookies.\*.sameSite | string | | |
action_result.data.\*.data.cookies.\*.secure | boolean | | True |
action_result.data.\*.data.cookies.\*.session | boolean | | False |
action_result.data.\*.data.cookies.\*.size | numeric | | 12 |
action_result.data.\*.data.cookies.\*.sourcePort | numeric | | 443 |
action_result.data.\*.data.cookies.\*.sourceScheme | string | | Secure |
action_result.data.\*.data.cookies.\*.value | string | | ARxQvcfS |
action_result.data.\*.data.globals.\*.prop | string | | onbeforexrselect |
action_result.data.\*.data.globals.\*.type | string | | object |
action_result.data.\*.data.links.\*.href | string | `url` | https://test.test |
action_result.data.\*.data.links.\*.text | string | | Feedback |
action_result.data.\*.data.requests.\*.initiatorInfo.host | string | | test.test |
action_result.data.\*.data.requests.\*.initiatorInfo.type | string | | parser |
action_result.data.\*.data.requests.\*.initiatorInfo.url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.request.documentURL | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.request.frameId | string | | 8956.1 |
action_result.data.\*.data.requests.\*.request.hasUserGesture | boolean | | False |
action_result.data.\*.data.requests.\*.request.initiator.columnNumber | numeric | | 88 |
action_result.data.\*.data.requests.\*.request.initiator.lineNumber | numeric | | 27 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.columnNumber | numeric | | 16 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.functionName | string | | |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.lineNumber | numeric | | 26 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.scriptId | string | | 31 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.request.initiator.type | string | | other |
action_result.data.\*.data.requests.\*.request.initiator.url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.request.loaderId | string | | 8956.1 |
action_result.data.\*.data.requests.\*.request.primaryRequest | boolean | | True |
action_result.data.\*.data.requests.\*.request.redirectResponse.encodedDataLength | numeric | | 295 |
action_result.data.\*.data.requests.\*.request.redirectResponse.fromPrefetchCache | boolean | | False |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.\* | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Connection | string | | keep-alive |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Length | string | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Date | string | | Mon, 10 May 2021 06:30:19 GMT |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Location | string | `url` | https://abc.test.test/v2/collectConsent?sessionId=123 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Server | string | | test |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Strict-Transport-Security | string | | max-age=31536000; includeSubDomains |
action_result.data.\*.data.requests.\*.request.redirectResponse.mimeType | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.protocol | string | `url` | http/1.1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.remoteIPAddress | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.remotePort | numeric | | 443 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept | string | | text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept-Encoding | string | | gzip, deflate, br |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept-Language | string | | en-US |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Cache-Control | string | | no-cache |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Connection | string | | keep-alive |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Cookie | string | | B=5m9tgmtg9hknr&b=3&s=6v; TEST=ARxQvcfS |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Host | string | | abc.test.test |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Dest | string | | document |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Mode | string | | navigate |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-User | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Upgrade-Insecure-Requests | string | | 1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.User-Agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.responseTime | numeric | | 1620628219732.224 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.certificateTransparencyCompliance | string | | unknown |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.issuer | string | | Test Authority |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.keyExchange | string | | ECDHE_RSA |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.keyExchangeGroup | string | | P-256 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.protocol | string | | TLS 1.2 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.sanList | string | | abc.test.test |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.subjectName | string | | abc.test.test |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.validFrom | numeric | | 1615766400 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.validTo | numeric | | 1631145599 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityState | string | | secure |
action_result.data.\*.data.requests.\*.request.redirectResponse.status | numeric | | 302 |
action_result.data.\*.data.requests.\*.request.redirectResponse.statusText | string | | Found |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.connectEnd | numeric | | 125.951 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.connectStart | numeric | | 7.534 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.dnsEnd | numeric | | 7.534 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.dnsStart | numeric | | 0.359 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.proxyEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.proxyStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.pushEnd | numeric | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.pushStart | numeric | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.receiveHeadersEnd | numeric | | 175.489 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.requestTime | numeric | | 31842294.2485 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sendEnd | numeric | | 126.079 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sendStart | numeric | | 126.003 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sslEnd | numeric | | 125.944 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sslStart | numeric | | 21.529 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerFetchStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerReady | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerRespondWithSettled | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.url | string | `url` | https://abc.test.test/consent?brandType=eu |
action_result.data.\*.data.requests.\*.request.request.hasPostData | boolean | | True |
action_result.data.\*.data.requests.\*.request.request.headers.\* | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Type | string | | application/csp-report |
action_result.data.\*.data.requests.\*.request.request.headers.Origin | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.request.request.headers.Referer | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.request.request.headers.Upgrade-Insecure-Requests | string | | 1 |
action_result.data.\*.data.requests.\*.request.request.headers.User-Agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.request.request.initialPriority | string | | VeryHigh |
action_result.data.\*.data.requests.\*.request.request.method | string | | GET |
action_result.data.\*.data.requests.\*.request.request.mixedContentType | string | | |
action_result.data.\*.data.requests.\*.request.request.postData | string | | {"csp-report":{"document-uri":"https://abc.test.test/v2?sessionId=123","referrer":"","violated-directive":"script-src-elem","effective-directive":"script-src-elem","original-policy":"default-src 'none'; block-all-mixed-content; connect-src https://abc.test.test 'self'; frame-ancestors 'none'; img-src 'self'; media-src 'none'; script-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q'; style-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q'; font-src 'self'; object-src 'none'; frame-src 'none'; report-uri https://abc.test.test/report","disposition":"report","blocked-uri":"https://xyz.test.test","status-code":0,"script-sample":""}} |
action_result.data.\*.data.requests.\*.request.request.postDataEntries.\*.bytes | string | | |
action_result.data.\*.data.requests.\*.request.request.referrerPolicy | string | | no-referrer-when-downgrade |
action_result.data.\*.data.requests.\*.request.request.url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.request.requestId | string | | 8956.1 |
action_result.data.\*.data.requests.\*.request.timestamp | numeric | | 25133387.317983 |
action_result.data.\*.data.requests.\*.request.type | string | | Document |
action_result.data.\*.data.requests.\*.request.wallTime | numeric | | 1502204689.61988 |
action_result.data.\*.data.requests.\*.requests.\*.documentURL | string | `url` | http://abc.test.test/ |
action_result.data.\*.data.requests.\*.requests.\*.frameId | string | `md5` | 041DE214F7F9878051EDF0C5717E0443 |
action_result.data.\*.data.requests.\*.requests.\*.hasUserGesture | boolean | | False |
action_result.data.\*.data.requests.\*.requests.\*.initiator.type | string | | other |
action_result.data.\*.data.requests.\*.requests.\*.loaderId | string | `md5` | DADC99FFA74AE5BA5FD45D5A205F78FE |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.asn | string | | 34010 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.country | string | | GB |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.date | string | | 2004-09-29 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.description | string | | TEST, GB |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.ip | string | `ip` `ipv6` | 2a00:1288:110:c305::1:8000 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.name | string | | TEST-IRD |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.registrar | string | | ripencc |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.route | string | | 2a00:1288:110::/48 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.encodedDataLength | numeric | | 1132 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.fromPrefetchCache | boolean | | False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.area | numeric | | 100 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.city | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.country | string | | GB |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.country_name | string | | United Kingdom |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.eu | string | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.ll | numeric | | -6.2591 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.range | numeric | | 875823103 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.region | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.timezone | string | | Europe/London |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Cache-Control | string | | no-store, no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Connection | string | | keep-alive |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Language | string | | en |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Length | string | | 8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Security-Policy | string | | frame-ancestors 'self' https://\*.test.test https://\*.abc.test https://\*.test.abc; sandbox allow-forms allow-same-origin allow-scripts allow-popups allow-popups-to-escape-sandbox allow-presentation; report-uri https://abc.test.test/beacon/csp?src=ats&region=US&lang=en-US; |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Type | string | | text/html |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Date | string | | Mon, 10 May 2021 06:30:19 GMT |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Location | string | `url` | https://abc.test.test/ |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Server | string | | ATS |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Set-Cookie | string | | B=5m9tgmtg9hknr&b=3&s=6v; expires=Tue, 10-May-2022 06:30:19 GMT; path=/; domain=.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Strict-Transport-Security | string | | max-age=31536000; includeSubDomains |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Frame-Options | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-XSS-Protection | string | | 1; report="https://abc.test.test" |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cache-control | string | | no-store |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-language | string | | en |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-length | string | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-security-policy | string | | frame-ancestors 'self' https://\*.abc.test https://\*.test.abc https://\*.test.test https://\*.abc.abc; sandbox allow-forms allow-same-origin allow-scripts allow-popups allow-popups-to-escape-sandbox allow-presentation; report-uri https://abc.test.test/beacon/csp?src=ats&region=US&lang=en-US; |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-type | string | | text/html |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.date | string | | Mon, 10 May 2021 06:30:19 GMT |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.expect-ct | string | | max-age=31536000, report-uri="http://abc.test.test/beacon/csp?src=t-expect-ct-report-only" |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.location | string | `url` | https://abc.test.test/?h=us |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.referrer-policy | string | | no-referrer-when-downgrade |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.server | string | | ATS |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.set-cookie | string | | RRC=st=1620628219&cnt=1; expires=Mon, 10-May-2021 06:30:49 GMT; path=/; domain=.abc.test.test; HttpOnly |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.strict-transport-security | string | | max-age=31536000 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-content-type-options | string | | nosniff |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-frame-options | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-xss-protection | string | | 1; mode=block |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.protocol | string | `url` | http/1.1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.rdns.ptr | string | | abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.remoteIPAddress | string | `ip` `ipv6` | [2a00:1288:110:c305::1:8000] |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.remotePort | numeric | | 80 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:authority | string | | abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:method | string | | GET |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:path | string | | / |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:scheme | string | `url` | https |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept | string | | text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept-Encoding | string | | gzip, deflate |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept-Language | string | | en-US |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Cache-Control | string | | no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Connection | string | | keep-alive |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Cookie | string | | B=5m9tgmtg9hknr&b=3&s=6v; TEST=ARxQvcfS |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Host | string | | abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Dest | string | | document |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Mode | string | | navigate |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-User | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Upgrade-Insecure-Requests | string | | 1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.User-Agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept | string | | text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept-encoding | string | | gzip, deflate, br |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept-language | string | | en-US |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.cache-control | string | | no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.cookie | string | | B=5m9tgmtg9hknr&b=3&s=6v |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-dest | string | | document |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-mode | string | | navigate |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-site | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-user | string | | ?1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.upgrade-insecure-requests | string | | 1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.user-agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.responseTime | numeric | | 1620628219395.843 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.certificateTransparencyCompliance | string | | unknown |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.issuer | string | | Test Authority |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.keyExchange | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.keyExchangeGroup | string | | X25519 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.protocol | string | | TLS 1.3 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.sanList | string | | abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.subjectName | string | | \*.abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.validFrom | numeric | | 1614556800 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.validTo | numeric | | 1629849599 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityState | string | | insecure |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.status | numeric | | 301 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.statusText | string | | Moved Permanently |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.connectEnd | numeric | | 32.743 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.connectStart | numeric | | 1.247 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.dnsEnd | numeric | | 1.247 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.dnsStart | numeric | | 0.357 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.proxyEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.proxyStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.pushEnd | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.pushStart | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.receiveHeadersEnd | numeric | | 68.337 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.requestTime | numeric | | 31842294.019283 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sendEnd | numeric | | 32.841 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sendStart | numeric | | 32.8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sslEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sslStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerFetchStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerReady | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerRespondWithSettled | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.url | string | `url` | http://abc.test.test/ |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Upgrade-Insecure-Requests | string | | 1 |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.User-Agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.requests.\*.request.initialPriority | string | | VeryHigh |
action_result.data.\*.data.requests.\*.requests.\*.request.method | string | | GET |
action_result.data.\*.data.requests.\*.requests.\*.request.mixedContentType | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.referrerPolicy | string | | strict-origin-when-cross-origin |
action_result.data.\*.data.requests.\*.requests.\*.request.url | string | `url` | http://abc.test.test/ |
action_result.data.\*.data.requests.\*.requests.\*.requestId | string | `md5` | DADC99FFA74AE5BA5FD45D5A205F78FE |
action_result.data.\*.data.requests.\*.requests.\*.timestamp | numeric | | 31842294.018831 |
action_result.data.\*.data.requests.\*.requests.\*.type | string | | Document |
action_result.data.\*.data.requests.\*.requests.\*.wallTime | numeric | | 1620628219.327166 |
action_result.data.\*.data.requests.\*.response.abp.source | string | | Test Inc. |
action_result.data.\*.data.requests.\*.response.abp.type | string | | annoyance |
action_result.data.\*.data.requests.\*.response.abp.url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.response.asn.asn | string | | 15169 |
action_result.data.\*.data.requests.\*.response.asn.country | string | | US |
action_result.data.\*.data.requests.\*.response.asn.date | string | | 2000-03-30 |
action_result.data.\*.data.requests.\*.response.asn.description | string | | TEST - Test Inc., US |
action_result.data.\*.data.requests.\*.response.asn.ip | string | `ip` `ipv6` | 2a00:1450:4001:814::200a |
action_result.data.\*.data.requests.\*.response.asn.name | string | | Test Inc. |
action_result.data.\*.data.requests.\*.response.asn.registrar | string | | arin |
action_result.data.\*.data.requests.\*.response.asn.route | string | | 34.240.0.0/13 |
action_result.data.\*.data.requests.\*.response.dataLength | numeric | | 29453 |
action_result.data.\*.data.requests.\*.response.encodedDataLength | numeric | | 29660 |
action_result.data.\*.data.requests.\*.response.failed.blockedReason | string | | mixed-content |
action_result.data.\*.data.requests.\*.response.failed.canceled | boolean | | True False |
action_result.data.\*.data.requests.\*.response.failed.errorText | string | | |
action_result.data.\*.data.requests.\*.response.failed.requestId | string | | 8956.7 |
action_result.data.\*.data.requests.\*.response.failed.timestamp | numeric | | 25133388.092608 |
action_result.data.\*.data.requests.\*.response.failed.type | string | | Stylesheet |
action_result.data.\*.data.requests.\*.response.geoip.area | numeric | | 1000 |
action_result.data.\*.data.requests.\*.response.geoip.city | string | | |
action_result.data.\*.data.requests.\*.response.geoip.country | string | | BG |
action_result.data.\*.data.requests.\*.response.geoip.country_name | string | | Bulgaria |
action_result.data.\*.data.requests.\*.response.geoip.eu | string | | 1 |
action_result.data.\*.data.requests.\*.response.geoip.ll | numeric | | 23.3333 |
action_result.data.\*.data.requests.\*.response.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.geoip.range | numeric | | 1275985919 |
action_result.data.\*.data.requests.\*.response.geoip.region | string | | |
action_result.data.\*.data.requests.\*.response.geoip.timezone | string | | Europe/Dublin |
action_result.data.\*.data.requests.\*.response.geoip.zip | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.hash | string | `sha256` | 824c215e931c70313b86d89c6ddb4c4c3b0a29604dc3a4f3ef287364e8d80607 |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.file | string | | jquery-migrate/1.4.1/jquery-migrate.min.js |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.project | string | | jquery-migrate |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.project_url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.source | string | | Test Inc. |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.response.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.rdns.ptr | string | | abc.test.test |
action_result.data.\*.data.requests.\*.response.requestId | string | | 8956.1 |
action_result.data.\*.data.requests.\*.response.response.encodedDataLength | numeric | | 83 |
action_result.data.\*.data.requests.\*.response.response.fromPrefetchCache | boolean | | False |
action_result.data.\*.data.requests.\*.response.response.headers.\* | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Accept-Ranges | string | | bytes |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Credentials | string | | true |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Headers | string | | origin,range,hdntl,hdnts |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Methods | string | | GET,POST,OPTIONS |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Origin | string | | * |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Expose-Headers | string | | Content-Range, X-ATLAS-MARKERS |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Max-Age | string | | 86400 |
action_result.data.\*.data.requests.\*.response.response.headers.Age | string | | 0 |
action_result.data.\*.data.requests.\*.response.response.headers.Alt-Svc | string | | h3-29=":443"; ma=93600,h3-Q050=":443"; ma=93600,quic=":443"; ma=93600; v="46,43" |
action_result.data.\*.data.requests.\*.response.response.headers.Cache-Control | string | | no-cache, no-store, must-revalidate |
action_result.data.\*.data.requests.\*.response.response.headers.Connection | string | | Upgrade, Keep-Alive |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Encoding | string | | gzip |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Length | string | | 25663 |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Security-Policy-Report-Only | string | | default-src 'none'; block-all-mixed-content; connect-src https://\*.abc.test.test https://\*.abc.abc.test 'self'; frame-ancestors 'none'; img-src 'self' https://test.img https://\*.img.test; media-src 'none'; script-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q'; style-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q'; |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Type | string | | image/png |
action_result.data.\*.data.requests.\*.response.response.headers.Date | string | | Tue, 08 Aug 2017 15:04:49 GMT |
action_result.data.\*.data.requests.\*.response.response.headers.ETag | string | | "52613b8-643f-5449ffc1d1aee" |
action_result.data.\*.data.requests.\*.response.response.headers.Etag | string | | "test1705564909da7f9eaf749dbbfbb1" |
action_result.data.\*.data.requests.\*.response.response.headers.Expect-CT | string | | max-age=31536000, report-uri="http://abc.test.test/beacon/csp?src=test-expect-ct-report-only" |
action_result.data.\*.data.requests.\*.response.response.headers.Expires | string | | 0 |
action_result.data.\*.data.requests.\*.response.response.headers.Keep-Alive | string | | timeout=5, max=300 |
action_result.data.\*.data.requests.\*.response.response.headers.Last-Modified | string | | Tue, 27 Dec 2016 08:53:23 GMT |
action_result.data.\*.data.requests.\*.response.response.headers.Pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.response.response.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Referrer-Policy | string | | strict-origin-when-cross-origin |
action_result.data.\*.data.requests.\*.response.response.headers.Server | string | | TestServer/1.4 |
action_result.data.\*.data.requests.\*.response.response.headers.Strict-Transport-Security | string | | max-age=31536000; includeSubDomains |
action_result.data.\*.data.requests.\*.response.response.headers.Timing-Allow-Origin | string | | * |
action_result.data.\*.data.requests.\*.response.response.headers.Upgrade | string | | h2,h2c |
action_result.data.\*.data.requests.\*.response.response.headers.Via | string | | 1.1 19e8b9893b635d62599a448aea7db.test.test |
action_result.data.\*.data.requests.\*.response.response.headers.X-Amz-Cf-Id | string | | W1YaaqDYWLSgU38zsXQ7Xt55F4FdEAEdd0YNqtTtvs3DkqA== |
action_result.data.\*.data.requests.\*.response.response.headers.X-Amz-Cf-Pop | string | | VIE50-C1 |
action_result.data.\*.data.requests.\*.response.response.headers.X-Cache | string | | HIT |
action_result.data.\*.data.requests.\*.response.response.headers.X-Content-Type-Options | string | | nosniff |
action_result.data.\*.data.requests.\*.response.response.headers.X-Frame-Options | string | | DENY |
action_result.data.\*.data.requests.\*.response.response.headers.X-LLID | string | `md5` | 40b5a42c1598c14b83edff465cd62db1 |
action_result.data.\*.data.requests.\*.response.response.headers.X-Powered-By | string | | Express |
action_result.data.\*.data.requests.\*.response.response.headers.X-XSS-Protection | string | | 1; mode=block |
action_result.data.\*.data.requests.\*.response.response.headers.accept-ranges | string | | bytes |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-methods | string | | GET |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-origin | string | | * |
action_result.data.\*.data.requests.\*.response.response.headers.age | string | | 520785 |
action_result.data.\*.data.requests.\*.response.response.headers.alt-svc | string | | quic=":443"; ma=2592000; v="39,38,37,36,35" |
action_result.data.\*.data.requests.\*.response.response.headers.ats-carp-promotion | string | | 1 |
action_result.data.\*.data.requests.\*.response.response.headers.cache-control | string | | no-cache, must-revalidate, max-age=0 |
action_result.data.\*.data.requests.\*.response.response.headers.content-encoding | string | | gzip |
action_result.data.\*.data.requests.\*.response.response.headers.content-length | string | | 29453 |
action_result.data.\*.data.requests.\*.response.response.headers.content-security-policy-report-only | string | | default-src 'self'; report-uri https://abc.test.test/beacon/csp?src=test |
action_result.data.\*.data.requests.\*.response.response.headers.content-type | string | | text/html; charset=UTF-8 |
action_result.data.\*.data.requests.\*.response.response.headers.date | string | | Tue, 08 Aug 2017 15:04:47 GMT |
action_result.data.\*.data.requests.\*.response.response.headers.etag | string | | "5267f53-62c-53514e7323a80" |
action_result.data.\*.data.requests.\*.response.response.headers.expect-ct | string | | max-age=31536000, report-uri="http://abc.test.test/beacon/csp?src=test-expect-ct-report-only" |
action_result.data.\*.data.requests.\*.response.response.headers.expires | string | | Wed, 11 Jan 1984 05:00:00 GMT |
action_result.data.\*.data.requests.\*.response.response.headers.last-modified | string | | Sun, 12 Jun 2016 13:39:38 GMT |
action_result.data.\*.data.requests.\*.response.response.headers.link | string | | <https://test.test/>; rel="https://api.test.test/" |
action_result.data.\*.data.requests.\*.response.response.headers.referrer-policy | string | | no-referrer-when-downgrade |
action_result.data.\*.data.requests.\*.response.response.headers.server | string | | TestServer/1.4 |
action_result.data.\*.data.requests.\*.response.response.headers.status | string | | 200 |
action_result.data.\*.data.requests.\*.response.response.headers.strict-transport-security | string | | max-age=15552000 |
action_result.data.\*.data.requests.\*.response.response.headers.timing-allow-origin | string | | * |
action_result.data.\*.data.requests.\*.response.response.headers.vary | string | | Accept-Encoding |
action_result.data.\*.data.requests.\*.response.response.headers.via | string | | 1.1 e8b17f734954ee4d46d2f302323482.test.test |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-cf-id | string | | Ob7ZSkPXvNH-2XbYyQH7lZFv5GbTNPkCXbSwtcOodIA== |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-cf-pop | string | | FRA53-C1 |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-id-2 | string | | ha+gqKNXBkV1gqr4AHswgx1OZSCdM7otKBZCL/JFLsojoWZn3JWVruarvQAhNV9ejI7FMh7PalI= |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-request-id | string | | 2KMY2R40Y5WJNG70 |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-server-side-encryption | string | | AES256 |
action_result.data.\*.data.requests.\*.response.response.headers.x-cache | string | | Hit from TestCloud |
action_result.data.\*.data.requests.\*.response.response.headers.x-content-type-options | string | | nosniff |
action_result.data.\*.data.requests.\*.response.response.headers.x-frame-options | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.response.response.headers.x-xss-protection | string | | 1; mode=block |
action_result.data.\*.data.requests.\*.response.response.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.response.response.protocol | string | `url` | spdy |
action_result.data.\*.data.requests.\*.response.response.remoteIPAddress | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.response.remotePort | numeric | | 443 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.\* | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept | string | | text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept-Encoding | string | | gzip, deflate, br |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept-Language | string | | en-US |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Cache-Control | string | | no-cache |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Connection | string | | keep-alive |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Cookie | string | | B=5m9tgmtg9hknr&b=3&s=6v; GUCS=ARxQvcfS |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Host | string | | abc.test.test |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Dest | string | | document |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Mode | string | | navigate |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-User | string | | ?1 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Upgrade-Insecure-Requests | string | | 1 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.User-Agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.response.response.responseTime | numeric | | 1620628219933.255 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.certificateTransparencyCompliance | string | | unknown |
action_result.data.\*.data.requests.\*.response.response.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.response.response.securityDetails.issuer | string | | Test Authority |
action_result.data.\*.data.requests.\*.response.response.securityDetails.keyExchange | string | | ECDHE_RSA |
action_result.data.\*.data.requests.\*.response.response.securityDetails.keyExchangeGroup | string | | P-256 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.protocol | string | | TLS 1.2 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.sanList | string | | www.test.test |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.hashAlgorithm | string | | SHA-256 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.logDescription | string | | Test 'test' log |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.logId | string | `sha256` | EE4BBDB775CE60BAE142691FABE19E66A30F7E5FB072D88300C47B897AA8FDCB |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.origin | string | | TLS extension |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.signatureAlgorithm | string | | ECDSA |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.signatureData | string | | 3045022100AB7CB0ADFD0A97125FCAFD75E16A0D7A963F97320318AFA76DFDDC760E67B0C602203C006DC6534D6C297F5B65897285E04AE6C303A5C3C6D7E7FAEF75A33E95CB23 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.status | string | | Verified |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.timestamp | numeric | | 1500976717935 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.subjectName | string | | test.test |
action_result.data.\*.data.requests.\*.response.response.securityDetails.validFrom | numeric | | 1498179660 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.validTo | numeric | | 1505955660 |
action_result.data.\*.data.requests.\*.response.response.securityHeaders.\*.name | string | | X-Content-Type-Options |
action_result.data.\*.data.requests.\*.response.response.securityHeaders.\*.value | string | | nosniff |
action_result.data.\*.data.requests.\*.response.response.securityState | string | | secure |
action_result.data.\*.data.requests.\*.response.response.status | numeric | | 200 |
action_result.data.\*.data.requests.\*.response.response.statusText | string | | |
action_result.data.\*.data.requests.\*.response.response.timing.connectEnd | numeric | | 151.193000376225 |
action_result.data.\*.data.requests.\*.response.response.timing.connectStart | numeric | | 69.2119970917702 |
action_result.data.\*.data.requests.\*.response.response.timing.dnsEnd | numeric | | 69.2119970917702 |
action_result.data.\*.data.requests.\*.response.response.timing.dnsStart | numeric | | 0.328999012708664 |
action_result.data.\*.data.requests.\*.response.response.timing.proxyEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.proxyStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.pushEnd | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.response.timing.pushStart | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.response.timing.receiveHeadersEnd | numeric | | 294.531997293234 |
action_result.data.\*.data.requests.\*.response.response.timing.requestTime | numeric | | 25133387.319129 |
action_result.data.\*.data.requests.\*.response.response.timing.sendEnd | numeric | | 151.373997330666 |
action_result.data.\*.data.requests.\*.response.response.timing.sendStart | numeric | | 151.313997805119 |
action_result.data.\*.data.requests.\*.response.response.timing.sslEnd | numeric | | 151.184998452663 |
action_result.data.\*.data.requests.\*.response.response.timing.sslStart | numeric | | 107.120998203754 |
action_result.data.\*.data.requests.\*.response.response.timing.workerFetchStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.workerReady | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.workerRespondWithSettled | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.workerStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.response.size | numeric | | 29453 |
action_result.data.\*.data.requests.\*.response.type | string | | Document |
action_result.data.\*.data.timing.beginNavigation | string | | 2017-08-08T15:04:49.619Z |
action_result.data.\*.data.timing.domContentEventFired | string | | 2017-08-08T15:04:50.903Z |
action_result.data.\*.data.timing.frameNavigated | string | | 2017-08-08T15:04:51.396Z |
action_result.data.\*.data.timing.frameStartedLoading | string | | 2017-08-08T15:04:50.903Z |
action_result.data.\*.data.timing.frameStoppedLoading | string | | 2017-08-08T15:04:52.370Z |
action_result.data.\*.data.timing.loadEventFired | string | | 2017-08-08T15:04:52.370Z |
action_result.data.\*.lists.asns | string | | 15169 |
action_result.data.\*.lists.certificates.\*.issuer | string | | Test Authority |
action_result.data.\*.lists.certificates.\*.sanList | string | | test.test |
action_result.data.\*.lists.certificates.\*.subjectName | string | | test.test |
action_result.data.\*.lists.certificates.\*.validFrom | numeric | | 1498179660 |
action_result.data.\*.lists.certificates.\*.validTo | numeric | | 1505955660 |
action_result.data.\*.lists.countries | string | | IE |
action_result.data.\*.lists.domains | string | | abc.test.test |
action_result.data.\*.lists.hashes | string | `sha256` | 581812adb789400372e69ee2a4aa7d58cdd009718a3faa114dd30dcc196fdeb8 |
action_result.data.\*.lists.ips | string | | 2a00:1450:4001:824::2003 |
action_result.data.\*.lists.linkDomains | string | | test.test |
action_result.data.\*.lists.servers | string | | ESF |
action_result.data.\*.lists.urls | string | `url` | https://test.test |
action_result.data.\*.meta.processors.abp.data.\*.source | string | | Test Inc. |
action_result.data.\*.meta.processors.abp.data.\*.type | string | | annoyance |
action_result.data.\*.meta.processors.abp.data.\*.url | string | `url` | https://test.test |
action_result.data.\*.meta.processors.abp.state | string | | done |
action_result.data.\*.meta.processors.asn.data.\*.asn | string | | 15169 |
action_result.data.\*.meta.processors.asn.data.\*.country | string | | US |
action_result.data.\*.meta.processors.asn.data.\*.date | string | | 2000-03-30 |
action_result.data.\*.meta.processors.asn.data.\*.description | string | | TEST - Test Inc., US |
action_result.data.\*.meta.processors.asn.data.\*.ip | string | `ip` `ipv6` | 2a00:1450:4001:814::200a |
action_result.data.\*.meta.processors.asn.data.\*.name | string | | Test Inc. |
action_result.data.\*.meta.processors.asn.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.asn.data.\*.route | string | | 34.240.0.0/13 |
action_result.data.\*.meta.processors.asn.state | string | | done |
action_result.data.\*.meta.processors.cdnjs.data.\*.hash | string | `sha256` | 48eb8b500ae6a38617b5738d2b3faec481922a7782246e31d2755c034a45cd5d |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches | string | | test-fonts/1.2.3/fonts/test-font.woff |
action_result.data.\*.meta.processors.cdnjs.state | string | | done |
action_result.data.\*.meta.processors.done.data.state | string | | done |
action_result.data.\*.meta.processors.done.state | string | | done |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.area | numeric | | 1000 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.city | string | | |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.country | string | | BG |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.country_name | string | | Bulgaria |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.eu | string | | 1 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.range | numeric | | 875823103 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.region | string | | |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.timezone | string | | Europe/Dublin |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.zip | numeric | | 0 |
action_result.data.\*.meta.processors.geoip.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.geoip.state | string | | done |
action_result.data.\*.meta.processors.gsb.data.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.gsb.data.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.gsb.data.matches.\*.threat.url | string | `url` | https://test.test |
action_result.data.\*.meta.processors.gsb.data.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.gsb.data.matches.\*.threatType | string | | SOCIAL_ENGINEERING |
action_result.data.\*.meta.processors.gsb.state | string | | done |
action_result.data.\*.meta.processors.rdns.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.rdns.data.\*.ptr | string | | abc.test.test |
action_result.data.\*.meta.processors.rdns.state | string | | done |
action_result.data.\*.meta.processors.wappa.state | string | | done |
action_result.data.\*.page.asn | string | | AS |
action_result.data.\*.page.asnname | string | | |
action_result.data.\*.page.city | string | | |
action_result.data.\*.page.country | string | | BG |
action_result.data.\*.page.domain | string | `domain` | test.test |
action_result.data.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.page.ptr | string | | abc.test.test |
action_result.data.\*.page.server | string | | TestServer/1.4 |
action_result.data.\*.page.url | string | `url` | https://test.test |
action_result.data.\*.stats.IPv6Percentage | numeric | | 75 |
action_result.data.\*.stats.adBlocked | numeric | | 2 |
action_result.data.\*.stats.domainStats.\*.count | numeric | | 54 |
action_result.data.\*.stats.domainStats.\*.countries | string | | IE |
action_result.data.\*.stats.domainStats.\*.domain | string | `domain` | test.test |
action_result.data.\*.stats.domainStats.\*.encodedSize | numeric | | 894416 |
action_result.data.\*.stats.domainStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.domainStats.\*.initiators | string | | test.test |
action_result.data.\*.stats.domainStats.\*.ips | string | | [2a00:1450:4001:814::200a] |
action_result.data.\*.stats.domainStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.domainStats.\*.size | numeric | | 889425 |
action_result.data.\*.stats.ipStats.\*.asn.asn | string | | 15169 |
action_result.data.\*.stats.ipStats.\*.asn.country | string | | US |
action_result.data.\*.stats.ipStats.\*.asn.date | string | | 2000-03-30 |
action_result.data.\*.stats.ipStats.\*.asn.description | string | | TEST - Test Inc., US |
action_result.data.\*.stats.ipStats.\*.asn.ip | string | | 2a00:1450:4001:814::200a |
action_result.data.\*.stats.ipStats.\*.asn.name | string | | Test Inc. |
action_result.data.\*.stats.ipStats.\*.asn.registrar | string | | arin |
action_result.data.\*.stats.ipStats.\*.asn.route | string | | 2a00:1288:110::/48 |
action_result.data.\*.stats.ipStats.\*.count | string | | |
action_result.data.\*.stats.ipStats.\*.countries | string | | IE |
action_result.data.\*.stats.ipStats.\*.domains | string | | abc.test.test |
action_result.data.\*.stats.ipStats.\*.encodedSize | numeric | | 894416 |
action_result.data.\*.stats.ipStats.\*.geoip.area | numeric | | 100 |
action_result.data.\*.stats.ipStats.\*.geoip.city | string | | |
action_result.data.\*.stats.ipStats.\*.geoip.country | string | | BG |
action_result.data.\*.stats.ipStats.\*.geoip.country_name | string | | Bulgaria |
action_result.data.\*.stats.ipStats.\*.geoip.eu | string | | 0 |
action_result.data.\*.stats.ipStats.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.stats.ipStats.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.geoip.range | numeric | | 1475903487 |
action_result.data.\*.stats.ipStats.\*.geoip.region | string | | |
action_result.data.\*.stats.ipStats.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.stats.ipStats.\*.geoip.zip | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.ipStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.ipStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.rdns.ptr | string | | abc.test.test |
action_result.data.\*.stats.ipStats.\*.redirects | numeric | | 3 |
action_result.data.\*.stats.ipStats.\*.requests | numeric | | 54 |
action_result.data.\*.stats.ipStats.\*.size | numeric | | 889425 |
action_result.data.\*.stats.malicious | numeric | | 51 |
action_result.data.\*.stats.protocolStats.\*.count | numeric | | 59 |
action_result.data.\*.stats.protocolStats.\*.countries | string | | BG |
action_result.data.\*.stats.protocolStats.\*.encodedSize | numeric | | 976819 |
action_result.data.\*.stats.protocolStats.\*.ips | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.protocolStats.\*.protocol | string | `url` | spdy |
action_result.data.\*.stats.protocolStats.\*.size | numeric | | 1056847 |
action_result.data.\*.stats.regDomainStats.\*.count | numeric | | 54 |
action_result.data.\*.stats.regDomainStats.\*.encodedSize | numeric | | 894416 |
action_result.data.\*.stats.regDomainStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.regDomainStats.\*.ips | string | | [2a00:1450:4001:814::200a] |
action_result.data.\*.stats.regDomainStats.\*.redirects | numeric | | 4 |
action_result.data.\*.stats.regDomainStats.\*.regDomain | string | `domain` | test.test |
action_result.data.\*.stats.regDomainStats.\*.size | numeric | | 889425 |
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.country | string | | GB |
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.domain | string | `domain` | maps |
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.failed | boolean | | True False |
action_result.data.\*.stats.resourceStats.\*.compression | string | | 1.0 |
action_result.data.\*.stats.resourceStats.\*.count | numeric | | 21 |
action_result.data.\*.stats.resourceStats.\*.countries | string | | BG |
action_result.data.\*.stats.resourceStats.\*.encodedSize | numeric | | 361619 |
action_result.data.\*.stats.resourceStats.\*.ips | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.resourceStats.\*.latency | numeric | | 0 |
action_result.data.\*.stats.resourceStats.\*.percentage | numeric | | 30 |
action_result.data.\*.stats.resourceStats.\*.size | numeric | | 366814 |
action_result.data.\*.stats.resourceStats.\*.type | string | | Script |
action_result.data.\*.stats.securePercentage | numeric | | 86 |
action_result.data.\*.stats.secureRequests | numeric | | 59 |
action_result.data.\*.stats.serverStats.\*.count | numeric | | 54 |
action_result.data.\*.stats.serverStats.\*.countries | string | | IE |
action_result.data.\*.stats.serverStats.\*.encodedSize | numeric | | 894416 |
action_result.data.\*.stats.serverStats.\*.ips | string | | [2a00:1450:4001:824::200a] |
action_result.data.\*.stats.serverStats.\*.server | string | | TestServer/1.4 |
action_result.data.\*.stats.serverStats.\*.size | numeric | | 889425 |
action_result.data.\*.stats.tlsStats.\*.count | numeric | | 59 |
action_result.data.\*.stats.tlsStats.\*.countries | string | | BG |
action_result.data.\*.stats.tlsStats.\*.encodedSize | numeric | | 976819 |
action_result.data.\*.stats.tlsStats.\*.ips | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | 4 |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | 55 |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | 17 |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | 3 |
action_result.data.\*.stats.tlsStats.\*.securityState | string | | secure |
action_result.data.\*.stats.tlsStats.\*.size | numeric | | 1056847 |
action_result.data.\*.stats.totalLinks | numeric | | 4 |
action_result.data.\*.stats.uniqCountries | numeric | | 2 |
action_result.data.\*.submitter.country | string | | US |
action_result.data.\*.task.domURL | string | `url` | https://urlscan.io/dom/86b7f70a-5039-419f-9aeb-8cba09404e92/ |
action_result.data.\*.task.method | string | | manual |
action_result.data.\*.task.options.useragent | string | | TestBrowser/7.0 |
action_result.data.\*.task.reportURL | string | `url` | https://urlscan.io/result/86b7f70a-5039-419f-9aeb-8cba09404e92/ |
action_result.data.\*.task.screenshotURL | string | `url` | https://urlscan.io/screenshots/86b7f70a-5039-419f-9aeb-8cba09404e92.png |
action_result.data.\*.task.source | string | | web |
action_result.data.\*.task.time | string | | 2017-08-08T15:04:49.501Z |
action_result.data.\*.task.url | string | `url` | https://test.test/index.html |
action_result.data.\*.task.userAgent | string | | TestBrowser/7.0 |
action_result.data.\*.task.uuid | string | `urlscan submission id` | 86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.task.visibility | string | | public |
action_result.data.\*.verdicts.community.score | numeric | | 0 |
action_result.data.\*.verdicts.community.votesBenign | numeric | | 0 |
action_result.data.\*.verdicts.community.votesMalicious | numeric | | 0 |
action_result.data.\*.verdicts.community.votesTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.benignTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.enginesTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.maliciousTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.score | numeric | | 0 |
action_result.data.\*.verdicts.overall.hasVerdicts | numeric | | 0 |
action_result.data.\*.verdicts.overall.malicious | boolean | | False |
action_result.data.\*.verdicts.overall.score | numeric | | 0 |
action_result.data.\*.verdicts.urlscan.malicious | boolean | | False |
action_result.data.\*.verdicts.urlscan.score | numeric | | 0 |
action_result.summary.added_tags_num | numeric | | 0 |
action_result.summary.report_uuid | string | `urlscan submission id` | value |
action_result.message | string | | Successfully retrieved information |
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
action_result.status | string | | success failed |
action_result.parameter.domain | string | `domain` | test.test |
action_result.data.\*.has_more | boolean | | False |
action_result.data.\*.results.\*.\_id | string | | 86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.results.\*.indexedAt | string | | 2021-02-14T15:16:53.879Z |
action_result.data.\*.results.\*.page.asn | string | | ASundefined |
action_result.data.\*.results.\*.page.asnname | string | | |
action_result.data.\*.results.\*.page.city | string | | |
action_result.data.\*.results.\*.page.country | string | | BG |
action_result.data.\*.results.\*.page.domain | string | `domain` | test.test |
action_result.data.\*.results.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.page.mimeType | string | | text/html |
action_result.data.\*.results.\*.page.ptr | string | | abc.test.test |
action_result.data.\*.results.\*.page.server | string | | TestServer/1.4 |
action_result.data.\*.results.\*.page.status | string | | 200 |
action_result.data.\*.results.\*.page.url | string | `url` | https://test.test |
action_result.data.\*.results.\*.result | string | `url` | https://urlscan.io/api/v1/result/86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.results.\*.screenshot | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.results.\*.stats.consoleMsgs | numeric | | 1 |
action_result.data.\*.results.\*.stats.dataLength | numeric | | 1082510 |
action_result.data.\*.results.\*.stats.encodedDataLength | numeric | | 1002482 |
action_result.data.\*.results.\*.stats.requests | numeric | | 69 |
action_result.data.\*.results.\*.stats.uniqCountries | numeric | | 3 |
action_result.data.\*.results.\*.stats.uniqIPs | numeric | | 5 |
action_result.data.\*.results.\*.task.domain | string | | abc.test.test |
action_result.data.\*.results.\*.task.method | string | | manual |
action_result.data.\*.results.\*.task.source | string | | web |
action_result.data.\*.results.\*.task.time | string | | 2017-08-08T15:04:49.501Z |
action_result.data.\*.results.\*.task.url | string | `url` | https://test.test |
action_result.data.\*.results.\*.task.uuid | string | | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.results.\*.task.visibility | string | | public |
action_result.data.\*.results.\*.uniq_countries | numeric | | 2 |
action_result.data.\*.took | numeric | | 25 |
action_result.data.\*.total | numeric | | 1 |
action_result.summary | string | | |
action_result.message | string | | Successfully retrieved information |
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
action_result.status | string | | success failed |
action_result.parameter.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.has_more | boolean | | False |
action_result.data.\*.results.\*.\_id | string | | 86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.results.\*.indexedAt | string | | 2021-02-25T20:59:59.079Z |
action_result.data.\*.results.\*.page.asn | string | | ASundefined |
action_result.data.\*.results.\*.page.asnname | string | | POWERNET-AS, BG |
action_result.data.\*.results.\*.page.city | string | | |
action_result.data.\*.results.\*.page.country | string | | BG |
action_result.data.\*.results.\*.page.domain | string | `domain` | test.test |
action_result.data.\*.results.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.page.mimeType | string | | text/html |
action_result.data.\*.results.\*.page.ptr | string | | abc.test.test |
action_result.data.\*.results.\*.page.server | string | | TestServer/1.4 |
action_result.data.\*.results.\*.page.status | string | | 200 |
action_result.data.\*.results.\*.page.url | string | `url` | https://test.test |
action_result.data.\*.results.\*.result | string | `url` | https://urlscan.io/api/v1/result/86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.results.\*.screenshot | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.results.\*.stats.consoleMsgs | numeric | | 1 |
action_result.data.\*.results.\*.stats.dataLength | numeric | | 1082510 |
action_result.data.\*.results.\*.stats.encodedDataLength | numeric | | 1002482 |
action_result.data.\*.results.\*.stats.requests | numeric | | 69 |
action_result.data.\*.results.\*.stats.uniqCountries | numeric | | 2 |
action_result.data.\*.results.\*.stats.uniqIPs | numeric | | 5 |
action_result.data.\*.results.\*.task.domain | string | | abc.test.test |
action_result.data.\*.results.\*.task.method | string | | manual |
action_result.data.\*.results.\*.task.source | string | | web |
action_result.data.\*.results.\*.task.time | string | | 2017-08-08T15:04:49.501Z |
action_result.data.\*.results.\*.task.url | string | `url` | https://test.test |
action_result.data.\*.results.\*.task.uuid | string | | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.results.\*.task.visibility | string | | public |
action_result.data.\*.results.\*.uniq_countries | numeric | | 2 |
action_result.data.\*.took | numeric | | 77 |
action_result.data.\*.total | numeric | | 104 |
action_result.summary | string | | |
action_result.message | string | | Successfully retrieved information |
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
action_result.status | string | | success failed |
action_result.parameter.custom_agent | string | | TestBrowser/7.0 |
action_result.parameter.get_result | boolean | | True False |
action_result.parameter.private | boolean | | True False |
action_result.parameter.addto_vault | boolean | | True False |
action_result.parameter.tags | string | | demotag1,demotag2 |
action_result.parameter.url | string | `url` `domain` | http://test.test |
action_result.data.\*.api | string | `url` | https://urlscan.io/api/v1/result/f04f2a29-d455-4830-874a-88191fb79352/ |
action_result.data.\*.data.console.\*.message.column | numeric | | 250 |
action_result.data.\*.data.console.\*.message.level | string | | log |
action_result.data.\*.data.console.\*.message.line | numeric | | 500 |
action_result.data.\*.data.console.\*.message.source | string | | console-api |
action_result.data.\*.data.console.\*.message.text | string | | %c%s color: red; background: yellow; font-size: 24px; WARNING! |
action_result.data.\*.data.console.\*.message.url | string | | /_/mss/boq-identity/_/js/k=boq-identity.ConsentUi.en.wbI8C7EDzao.es5.O/am=CwAQ/d=1/excm=\_b,\_tp,mainview/ed=1/dg=0/wt=2/rs=AOaEmlFuEZIwaq7Xwoq3xS-5oRO8y6-S_A/m=\_b,\_tp |
action_result.data.\*.data.cookies.\*.domain | string | `domain` | test.test |
action_result.data.\*.data.cookies.\*.expires | numeric | | 1517901199000 |
action_result.data.\*.data.cookies.\*.httpOnly | boolean | | True False |
action_result.data.\*.data.cookies.\*.name | string | | \_\_utmz |
action_result.data.\*.data.cookies.\*.path | string | | / |
action_result.data.\*.data.cookies.\*.priority | string | | Medium |
action_result.data.\*.data.cookies.\*.sameParty | boolean | | False |
action_result.data.\*.data.cookies.\*.sameSite | string | | |
action_result.data.\*.data.cookies.\*.secure | boolean | | True False |
action_result.data.\*.data.cookies.\*.session | boolean | | True False |
action_result.data.\*.data.cookies.\*.size | numeric | | 76 |
action_result.data.\*.data.cookies.\*.sourcePort | numeric | | 443 |
action_result.data.\*.data.cookies.\*.sourceScheme | string | | Secure |
action_result.data.\*.data.cookies.\*.value | string | | 215733128.1502133199.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none) |
action_result.data.\*.data.globals.\*.prop | string | | onbeforexrselect |
action_result.data.\*.data.globals.\*.type | string | | object |
action_result.data.\*.data.links.\*.href | string | `url` | http://test.test |
action_result.data.\*.data.links.\*.text | string | | stor perde |
action_result.data.\*.data.requests.\*.initiatorInfo.host | string | | www.test.test |
action_result.data.\*.data.requests.\*.initiatorInfo.type | string | | parser |
action_result.data.\*.data.requests.\*.initiatorInfo.url | string | `url` | http://test.test |
action_result.data.\*.data.requests.\*.request.documentURL | string | `url` | http://test.test |
action_result.data.\*.data.requests.\*.request.frameId | string | | 24696.1 |
action_result.data.\*.data.requests.\*.request.hasUserGesture | boolean | | False |
action_result.data.\*.data.requests.\*.request.initiator.columnNumber | numeric | | 88 |
action_result.data.\*.data.requests.\*.request.initiator.lineNumber | numeric | | 27 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.columnNumber | numeric | | 386 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.functionName | string | | lb |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.lineNumber | numeric | | 13 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.scriptId | string | | 40 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.request.initiator.type | string | | other |
action_result.data.\*.data.requests.\*.request.initiator.url | string | `url` | http://test.test |
action_result.data.\*.data.requests.\*.request.loaderId | string | | 24696.1 |
action_result.data.\*.data.requests.\*.request.primaryRequest | boolean | | True |
action_result.data.\*.data.requests.\*.request.redirectResponse.encodedDataLength | numeric | | 233 |
action_result.data.\*.data.requests.\*.request.redirectResponse.fromPrefetchCache | boolean | | False |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.\* | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Connection | string | | Keep-Alive |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Length | string | | 273 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Type | string | | text/html; charset=iso-8859-1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Date | string | | Mon, 07 Aug 2017 19:13:18 GMT |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Keep-Alive | string | | timeout=1, max=100 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Location | string | `url` | http://test.test |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Non-Authoritative-Reason | string | | HSTS |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Server | string | | TestServer/1.4 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Strict-Transport-Security | string | | max-age=31536000; includeSubDomains |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Transfer-Encoding | string | | chunked |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-DIS-Request-ID | string | | 090e3c74f52631470b8375f9d7f2da55 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-credentials | string | | true |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-origin | string | | https://abc.test.test |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.alt-svc | string | | h3-29=":443"; ma=2592000,h3-T051=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43" |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cache-control | string | | no-cache, no-store, max-age=0, must-revalidate |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-length | string | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-type | string | | application/binary |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cross-origin-resource-policy | string | | cross-origin |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.date | string | | Mon, 10 May 2021 10:52:44 GMT |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.expires | string | | Mon, 01 Jan 1990 00:00:00 GMT |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.location | string | `url` | https://consent.test.test/?h=123 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.p3p | string | | CP="This is not a P3 policy! See abc.test.test for more info." |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.permissions-policy | string | | ch-ua-full-version=\*, ch-ua-platform=\*, ch-ua-platform-version=\*, ch-ua-arch=\*, ch-ua-model=\* |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.server | string | | ESF |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.set-cookie | string | | CONSENT=PENDING+166; expires=Fri, 01-Jan-2038 00:00:00 GMT; path=/; domain=.test.test; Secure |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.strict-transport-security | string | | max-age=31536000 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.timing-allow-origin | string | | * |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-content-type-options | string | | nosniff |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-frame-options | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-xss-protection | string | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.request.redirectResponse.protocol | string | `url` | http/1.1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.remoteIPAddress | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.remotePort | numeric | | 80 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:authority | string | | abc.test.test |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:method | string | | GET |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:path | string | | / |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:scheme | string | `url` | https |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept | string | | text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept-Encoding | string | | gzip, deflate, br |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept-Language | string | | en-US |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Cache-Control | string | | no-cache |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Connection | string | | keep-alive |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Cookie | string | | B=dv5klk1g9hcet&b=3&s=t9; GUCS=AVkRFB1g |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Host | string | | abc.test.test |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Dest | string | | document |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Mode | string | | navigate |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-User | string | | ?1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Upgrade-Insecure-Requests | string | | 1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.User-Agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.accept | string | | text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.accept-encoding | string | | gzip, deflate, br |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.accept-language | string | | en-US |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.cache-control | string | | no-cache |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-dest | string | | document |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-mode | string | | navigate |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-site | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-user | string | | ?1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.upgrade-insecure-requests | string | | 1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.user-agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.responseTime | numeric | | 1620619741414.982 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.certificateTransparencyCompliance | string | | unknown |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.issuer | string | | Test Authority |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.keyExchange | string | | ECDHE_RSA |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.keyExchangeGroup | string | | P-256 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.protocol | string | | TLS 1.2 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.sanList | string | | abc.test.test |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.subjectName | string | | abc.test.test |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.validFrom | numeric | | 1615766400 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.validTo | numeric | | 1631145599 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityState | string | | neutral |
action_result.data.\*.data.requests.\*.request.redirectResponse.status | numeric | | 302 |
action_result.data.\*.data.requests.\*.request.redirectResponse.statusText | string | | Found |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.connectEnd | numeric | | 84.8650000989437 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.connectStart | numeric | | 0.484999269247055 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.dnsEnd | numeric | | 0.484999269247055 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.dnsStart | numeric | | 0.0520013272762299 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.proxyEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.proxyStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.pushEnd | numeric | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.pushStart | numeric | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.receiveHeadersEnd | numeric | | 170.065999031067 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.requestTime | numeric | | 25061895.849275 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sendEnd | numeric | | 84.9450007081032 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sendStart | numeric | | 84.9259980022907 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sslEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sslStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerFetchStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerReady | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerRespondWithSettled | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.url | string | `url` | http://test.test |
action_result.data.\*.data.requests.\*.request.request.hasPostData | boolean | | True |
action_result.data.\*.data.requests.\*.request.request.headers.\* | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Type | string | | application/csp-report |
action_result.data.\*.data.requests.\*.request.request.headers.Origin | string | `url` | abc.test.test |
action_result.data.\*.data.requests.\*.request.request.headers.Referer | string | `url` | http://test.test |
action_result.data.\*.data.requests.\*.request.request.headers.Upgrade-Insecure-Requests | string | | 1 |
action_result.data.\*.data.requests.\*.request.request.headers.User-Agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.request.request.headers.X-Same-Domain | string | `domain` | 1 |
action_result.data.\*.data.requests.\*.request.request.initialPriority | string | | VeryHigh |
action_result.data.\*.data.requests.\*.request.request.method | string | | GET |
action_result.data.\*.data.requests.\*.request.request.mixedContentType | string | | |
action_result.data.\*.data.requests.\*.request.request.postData | string | | {"csp-report":{"document-uri":"https://abc.test.test/v2?sessionId=123","referrer":"","violated-directive":"script-src-elem","effective-directive":"script-src-elem","original-policy":"default-src 'none'; block-all-mixed-content; connect-src https://abc.test.test 'self'; frame-ancestors 'none'; img-src 'self'; media-src 'none'; script-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q'; style-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q'; font-src 'self'; object-src 'none'; frame-src 'none'; report-uri https://abc.test.test/report","disposition":"report","blocked-uri":"https://xyz.test.test","status-code":0,"script-sample":""}} |
action_result.data.\*.data.requests.\*.request.request.postDataEntries.\*.bytes | string | | |
action_result.data.\*.data.requests.\*.request.request.referrerPolicy | string | | no-referrer-when-downgrade |
action_result.data.\*.data.requests.\*.request.request.url | string | `url` | http://test.test |
action_result.data.\*.data.requests.\*.request.requestId | string | | 24696.1 |
action_result.data.\*.data.requests.\*.request.timestamp | numeric | | 25061896.019653 |
action_result.data.\*.data.requests.\*.request.type | string | | Document |
action_result.data.\*.data.requests.\*.request.wallTime | numeric | | 1502133198.32155 |
action_result.data.\*.data.requests.\*.requests.\*.documentURL | string | `url` | http://abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.frameId | string | `md5` | 6160E8BDE221F1BEA3E15CF13AD40EAF |
action_result.data.\*.data.requests.\*.requests.\*.hasUserGesture | boolean | | False |
action_result.data.\*.data.requests.\*.requests.\*.initiator.columnNumber | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.lineNumber | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.columnNumber | numeric | | 493 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.functionName | string | | zg |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.lineNumber | numeric | | 532 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.scriptId | string | | 8 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.url | string | | https://abc.test.test/s/player/ |
action_result.data.\*.data.requests.\*.requests.\*.initiator.type | string | | other |
action_result.data.\*.data.requests.\*.requests.\*.initiator.url | string | | https://abc.test.test/embed/abc |
action_result.data.\*.data.requests.\*.requests.\*.loaderId | string | `md5` | 0B0AA65E4A0D942DBF007F12F2B5081F |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.asn | string | | 34010 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.country | string | | GB |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.date | string | | 2004-09-29 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.description | string | | TEST-IRD, GB |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.ip | string | `ip` `ipv6` | 2a00:1288:110:c305::1:8000 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.name | string | | TEST-IRD |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.registrar | string | | ripencc |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.encodedDataLength | numeric | | 1132 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.fromPrefetchCache | boolean | | False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.area | numeric | | 100 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.city | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.country | string | | GB |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.country_name | string | | United Kingdom |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.eu | string | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.ll | numeric | | -6.2591 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.range | numeric | | 780744703 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.region | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.timezone | string | | Europe/London |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Cache-Control | string | | no-store, no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Connection | string | | keep-alive |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Language | string | | en |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Length | string | | 8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Security-Policy | string | | frame-ancestors 'self' https://\*.abc.test https://\*.test.abc https://\*.test.test https://\*.abc.abc; sandbox allow-forms allow-same-origin allow-scripts allow-popups allow-popups-to-escape-sandbox allow-presentation; report-uri https://abc.test.test/beacon/csp?src=ats&region=US&lang=en-US; |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Type | string | | text/html |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Date | string | | Mon, 10 May 2021 04:09:01 GMT |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Keep-Alive | string | | timeout=20 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Location | string | `url` | https://abc.test.test/ |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Non-Authoritative-Reason | string | | HSTS |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Server | string | | ATS |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Set-Cookie | string | | B=dv5klk1g9hcet&b=3&s=t9; expires=Tue, 10-May-2022 04:09:01 GMT; path=/; domain=.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Strict-Transport-Security | string | | max-age=31536000; includeSubDomains |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Transfer-Encoding | string | | chunked |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-DIS-Request-ID | string | | 99b17817a2924a8349438143b10d69af |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Frame-Options | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-XSS-Protection | string | | 1; report="https://abc.test.test/beacon/csp?src=ftest" |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-credentials | string | | true |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-origin | string | | https://abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.alt-svc | string | | h3-29=":443"; ma=2592000,h3-T051=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43" |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cache-control | string | | no-store |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-language | string | | en |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-length | string | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-security-policy | string | | frame-ancestors 'self' https://\*.abc.test https://\*.test.abc https://\*.test.test https://\*.abc.abc; sandbox allow-forms allow-same-origin allow-scripts allow-popups allow-popups-to-escape-sandbox allow-presentation; report-uri https://abc.test.test/beacon/csp?src=ats&region=US&lang=en-US; |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-type | string | | text/html |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cross-origin-resource-policy | string | | cross-origin |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.date | string | | Mon, 10 May 2021 04:09:01 GMT |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.expect-ct | string | | max-age=31536000, report-uri="http://abc.test.test/beacon/csp?src=t-expect-ct-report-only" |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.expires | string | | Mon, 01 Jan 1990 00:00:00 GMT |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.location | string | `url` | https://abc.test.test/?h=us |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.p3p | string | | CP="This is not a P3 policy! See abc.test.test for more info." |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.permissions-policy | string | | ch-ua-full-version=\*, ch-ua-platform=\*, ch-ua-platform-version=\*, ch-ua-arch=\*, ch-ua-model=\* |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.referrer-policy | string | | no-referrer-when-downgrade |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.server | string | | ATS |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.set-cookie | string | | RRC=st=1620619741&cnt=1; expires=Mon, 10-May-2021 04:09:31 GMT; path=/; domain=.abc.test.test; HttpOnly |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.strict-transport-security | string | | max-age=31536000 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.timing-allow-origin | string | | * |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-content-type-options | string | | nosniff |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-frame-options | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-xss-protection | string | | 1; mode=block |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.protocol | string | `url` | http/1.1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.rdns.ptr | string | | abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.remoteIPAddress | string | `ip` `ipv6` | [2a00:1288:110:c305::1:8000] |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.remotePort | numeric | | 80 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:authority | string | | abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:method | string | | GET |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:path | string | | / |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:scheme | string | `url` | https |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept | string | | text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept-Encoding | string | | gzip, deflate |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept-Language | string | | en-US |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Cache-Control | string | | no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Connection | string | | keep-alive |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Cookie | string | | B=dv5klk1g9hcet&b=3&s=t9; GUCS=AVkRFB1g |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Host | string | | abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Dest | string | | document |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Mode | string | | navigate |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-User | string | | ?1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Upgrade-Insecure-Requests | string | | 1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.User-Agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept | string | | text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept-encoding | string | | gzip, deflate, br |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept-language | string | | en-US |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.cache-control | string | | no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.cookie | string | | B=dv5klk1g9hcet&b=3&s=t9 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-dest | string | | document |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-mode | string | | navigate |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-site | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-user | string | | ?1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.upgrade-insecure-requests | string | | 1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.user-agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.responseTime | numeric | | 1620619741065.401 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.certificateTransparencyCompliance | string | | unknown |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.issuer | string | | Test Authority |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.keyExchange | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.keyExchangeGroup | string | | X25519 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.protocol | string | | TLS 1.3 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.sanList | string | | abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.subjectName | string | | \*.abc.test.test |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.validFrom | numeric | | 1614556800 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.validTo | numeric | | 1629849599 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityState | string | | insecure |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.status | numeric | | 301 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.statusText | string | | Moved Permanently |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.connectEnd | numeric | | 31.252 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.connectStart | numeric | | 1.22 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.dnsEnd | numeric | | 1.22 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.dnsStart | numeric | | 0.231 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.proxyEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.proxyStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.pushEnd | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.pushStart | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.receiveHeadersEnd | numeric | | 64.224 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.requestTime | numeric | | 31833815.69294 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sendEnd | numeric | | 31.332 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sendStart | numeric | | 31.292 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sslEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sslStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerFetchStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerReady | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerRespondWithSettled | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.url | string | `url` | http://abc.test.test/ |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Referer | string | | https://abc.test.test/embed/abc |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Upgrade-Insecure-Requests | string | | 1 |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.User-Agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.requests.\*.request.initialPriority | string | | VeryHigh |
action_result.data.\*.data.requests.\*.requests.\*.request.method | string | | GET |
action_result.data.\*.data.requests.\*.requests.\*.request.mixedContentType | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.referrerPolicy | string | | strict-origin-when-cross-origin |
action_result.data.\*.data.requests.\*.requests.\*.request.url | string | `url` | http://abc.test.test/ |
action_result.data.\*.data.requests.\*.requests.\*.requestId | string | `md5` | 0B0AA65E4A0D942DBF007F12F2B5081F |
action_result.data.\*.data.requests.\*.requests.\*.timestamp | numeric | | 31833815.69249 |
action_result.data.\*.data.requests.\*.requests.\*.type | string | | Document |
action_result.data.\*.data.requests.\*.requests.\*.wallTime | numeric | | 1620619741.000826 |
action_result.data.\*.data.requests.\*.response.abp.source | string | | Test Inc. |
action_result.data.\*.data.requests.\*.response.abp.type | string | | annoyance |
action_result.data.\*.data.requests.\*.response.abp.url | string | `url` | http://test.test |
action_result.data.\*.data.requests.\*.response.asn.asn | string | | 43260 |
action_result.data.\*.data.requests.\*.response.asn.country | string | | TR |
action_result.data.\*.data.requests.\*.response.asn.date | string | | 2007-07-04 |
action_result.data.\*.data.requests.\*.response.asn.description | string | | DGN, TR |
action_result.data.\*.data.requests.\*.response.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.asn.name | string | | DGN |
action_result.data.\*.data.requests.\*.response.asn.registrar | string | | Test Authority |
action_result.data.\*.data.requests.\*.response.asn.route | string | | 34.248.0.0/13 |
action_result.data.\*.data.requests.\*.response.dataLength | numeric | | 48900 |
action_result.data.\*.data.requests.\*.response.encodedDataLength | numeric | | 10586 |
action_result.data.\*.data.requests.\*.response.failed.canceled | boolean | | True False |
action_result.data.\*.data.requests.\*.response.failed.errorText | string | | |
action_result.data.\*.data.requests.\*.response.failed.requestId | string | | 24696.156 |
action_result.data.\*.data.requests.\*.response.failed.timestamp | numeric | | 25061896.916161 |
action_result.data.\*.data.requests.\*.response.failed.type | string | | Document |
action_result.data.\*.data.requests.\*.response.geoip.area | numeric | | 1000 |
action_result.data.\*.data.requests.\*.response.geoip.city | string | | Bursa |
action_result.data.\*.data.requests.\*.response.geoip.country | string | | TR |
action_result.data.\*.data.requests.\*.response.geoip.country_name | string | | Turkey |
action_result.data.\*.data.requests.\*.response.geoip.eu | string | | 1 |
action_result.data.\*.data.requests.\*.response.geoip.ll | numeric | | -8 |
action_result.data.\*.data.requests.\*.response.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.geoip.range | numeric | | 1167286271 |
action_result.data.\*.data.requests.\*.response.geoip.region | string | | 16 |
action_result.data.\*.data.requests.\*.response.geoip.timezone | string | | Europe/Dublin |
action_result.data.\*.data.requests.\*.response.geoip.zip | numeric | | 16245 |
action_result.data.\*.data.requests.\*.response.hash | string | `sha256` | 90e62949116352899d321b982d3c8dd6e269538d9832a82e86b6f08b10f54883 |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.file | string | | mediaelement/2.0.0/jquery.js |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.project | string | | mediaelement |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.project_url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.source | string | | Test Inc. |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.url | string | `url` | https://test.test |
action_result.data.\*.data.requests.\*.response.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.rdns.ptr | string | | abc.test.test |
action_result.data.\*.data.requests.\*.response.requestId | string | | 24696.1 |
action_result.data.\*.data.requests.\*.response.response.encodedDataLength | numeric | | 261 |
action_result.data.\*.data.requests.\*.response.response.fromPrefetchCache | boolean | | False |
action_result.data.\*.data.requests.\*.response.response.headers.\* | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Accept-Ranges | string | | bytes |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Credentials | string | | true |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Headers | string | | origin,range,hdntl,hdnts |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Methods | string | | GET,POST,OPTIONS |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Origin | string | | * |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Expose-Headers | string | | Content-Range, X-ATLAS-MARKERS |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Max-Age | string | | 86400 |
action_result.data.\*.data.requests.\*.response.response.headers.Age | string | | 0 |
action_result.data.\*.data.requests.\*.response.response.headers.Alt-Svc | string | | h3-29=":443"; ma=93600,h3-Q050=":443"; ma=93600,quic=":443"; ma=93600; v="46,43" |
action_result.data.\*.data.requests.\*.response.response.headers.Cache-Control | string | | no-cache, no-store, must-revalidate |
action_result.data.\*.data.requests.\*.response.response.headers.Connection | string | | Keep-Alive |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Encoding | string | | gzip |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Length | string | | 10586 |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Security-Policy-Report-Only | string | | default-src 'none'; block-all-mixed-content; connect-src https://\*.abc.test.test https://\*.abc.abc.test 'self'; frame-ancestors 'none'; img-src 'self' https://test.img https://\*.img.test; media-src 'none'; script-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q'; style-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q'; |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Type | string | | text/html |
action_result.data.\*.data.requests.\*.response.response.headers.Date | string | | Mon, 07 Aug 2017 19:13:18 GMT |
action_result.data.\*.data.requests.\*.response.response.headers.ETag | string | | "5c17f0-1bf5-4bc7627477580" |
action_result.data.\*.data.requests.\*.response.response.headers.Etag | string | | "test91705564909da7f9eaf749dbbfbb1" |
action_result.data.\*.data.requests.\*.response.response.headers.Expect-CT | string | | max-age=31536000, report-uri="http://abc.test.test/beacon/csp?src=test-expect-ct-report-only" |
action_result.data.\*.data.requests.\*.response.response.headers.Expires | string | | 0 |
action_result.data.\*.data.requests.\*.response.response.headers.Keep-Alive | string | | timeout=1, max=99 |
action_result.data.\*.data.requests.\*.response.response.headers.Last-Modified | string | | Fri, 30 Mar 2012 13:52:38 GMT |
action_result.data.\*.data.requests.\*.response.response.headers.P3P | string | | CP="NON DSP COR ADMa OUR IND UNI COM NAV INT" |
action_result.data.\*.data.requests.\*.response.response.headers.Pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.response.response.headers.Public-Key-Pins-Report-Only | string | | max-age=2592000; pin-sha256="testyxl4A1/XHrKNBmc8bTk7y4FB/GLJuNAzCqY="; pin-sha256="I/Lt/testanjCvj5EqXls2lOaThEA0H2Bg4BT/o="; pin-sha256="testBWM9UZfyddvDfoxL+8lpNyoUB2ptGtn0fv6G2Q="; pin-sha256="test/qfTwq3lFNd3IpaqLHZbh2ZNCLluVzmeNkcpw="; pin-sha256="testIOVNa9ihaBciRC7XHjliYS9VwUGOIud4PB18="; pin-sha256="testXyFXFkWm61cF4HPW8S0srS9j0aSqN0k4AP+4A="; pin-sha256="testzEBnELx/9lOEQ2e6OZO/QNb6VSSX2XHA3E7A="; pin-sha256="testvh0OioIruIfF4kMPnBqrS2rdiVPl/s2uC/CY="; pin-sha256="r/testpVdm+u/ko/xzOMo1bk4TyHIlByibiA5E="; pin-sha256="testwDOxcBXrQcntwu+kYFiVkOaezL0WYEZ3anJc="; includeSubdomains; report-uri="http://abc.test.test/beacon/csp?src=test-hpkp-report-only" |
action_result.data.\*.data.requests.\*.response.response.headers.Referrer-Policy | string | | strict-origin-when-cross-origin |
action_result.data.\*.data.requests.\*.response.response.headers.Server | string | | TestServer/1.4 |
action_result.data.\*.data.requests.\*.response.response.headers.Strict-Transport-Security | string | | max-age=31536000; includeSubDomains |
action_result.data.\*.data.requests.\*.response.response.headers.Timing-Allow-Origin | string | | * |
action_result.data.\*.data.requests.\*.response.response.headers.Transfer-Encoding | string | | chunked |
action_result.data.\*.data.requests.\*.response.response.headers.Vary | string | | Accept-Encoding,User-Agent |
action_result.data.\*.data.requests.\*.response.response.headers.Via | string | | 1.1 9c157874a076ffdde5f5a44371f3a1.test.test |
action_result.data.\*.data.requests.\*.response.response.headers.X-Amz-Cf-Id | string | | wznqqSUHDRcnnyCbk9Dimhb-WD6cpBAdjEUd2PE58mwE7HIv2BIw== |
action_result.data.\*.data.requests.\*.response.response.headers.X-Amz-Cf-Pop | string | | VIE50-C1 |
action_result.data.\*.data.requests.\*.response.response.headers.X-Cache | string | | HIT |
action_result.data.\*.data.requests.\*.response.response.headers.X-Content-Type-Options | string | | nosniff |
action_result.data.\*.data.requests.\*.response.response.headers.X-DIS-Request-ID | string | | 9137843c7fc8d206d8a5f450cc63f525 |
action_result.data.\*.data.requests.\*.response.response.headers.X-Frame-Options | string | | DENY |
action_result.data.\*.data.requests.\*.response.response.headers.X-LLID | string | `md5` | 7d093909d3419b732aeaa85b2f081282 |
action_result.data.\*.data.requests.\*.response.response.headers.X-Powered-By | string | | PHP/5.2.17 |
action_result.data.\*.data.requests.\*.response.response.headers.X-XSS-Protection | string | | 1; mode=block |
action_result.data.\*.data.requests.\*.response.response.headers.accept-ranges | string | | bytes |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-credentials | string | | true |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-headers | string | | X-Playlog-Web |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-method | string | | OPTIONS |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-methods | string | | GET |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-origin | string | `url` | * |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-expose-headers | string | | X-FB-Content-MD5 |
action_result.data.\*.data.requests.\*.response.response.headers.age | string | | 734 |
action_result.data.\*.data.requests.\*.response.response.headers.alt-svc | string | | quic=":443"; ma=2592000; v="39,38,37,36,35" |
action_result.data.\*.data.requests.\*.response.response.headers.ats-carp-promotion | string | | 1 |
action_result.data.\*.data.requests.\*.response.response.headers.cache-control | string | | private, max-age=1800, stale-while-revalidate=1800 |
action_result.data.\*.data.requests.\*.response.response.headers.content-disposition | string | | attachment; filename="response.bin"; filename\*=UTF-8''response.bin |
action_result.data.\*.data.requests.\*.response.response.headers.content-encoding | string | | gzip |
action_result.data.\*.data.requests.\*.response.response.headers.content-length | string | | 16022 |
action_result.data.\*.data.requests.\*.response.response.headers.content-md5 | string | | 9Bs4q2xta3z6+p7pgFz0Ww== |
action_result.data.\*.data.requests.\*.response.response.headers.content-security-policy | string | | default-src * data: blob:;script-src \*.test.test \*.test2.test 127.0.0.1:\* 'unsafe-inline' 'unsafe-eval' 'self'; |
action_result.data.\*.data.requests.\*.response.response.headers.content-security-policy-report-only | string | | default-src 'self'; report-uri https://abc.test.test/beacon/csp?src=test |
action_result.data.\*.data.requests.\*.response.response.headers.content-type | string | | application/javascript; charset=utf-8 |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-opener-policy-report-only | string | | unsafe-none; report-to="ConsentUi" |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-resource-policy | string | | same-site |
action_result.data.\*.data.requests.\*.response.response.headers.date | string | | Mon, 07 Aug 2017 19:13:18 GMT |
action_result.data.\*.data.requests.\*.response.response.headers.etag | string | | "test4c7de07fe8def6029af1192b2d" |
action_result.data.\*.data.requests.\*.response.response.headers.expect-ct | string | | max-age=31536000, report-uri="http://cabc.test.test/beacon/csp?src=test-expect-ct-report-only" |
action_result.data.\*.data.requests.\*.response.response.headers.expires | string | | Mon, 07 Aug 2017 19:13:18 GMT |
action_result.data.\*.data.requests.\*.response.response.headers.last-modified | string | | Tue, 01 Aug 2017 03:25:32 GMT |
action_result.data.\*.data.requests.\*.response.response.headers.link | string | | <https://abc.test.test>; rel=preconnect; crossorigin |
action_result.data.\*.data.requests.\*.response.response.headers.p3p | string | | CP="This is not a P3P policy! See https://support.test.test for more info." |
action_result.data.\*.data.requests.\*.response.response.headers.pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.response.response.headers.public-key-pins-report-only | string | | max-age=500; pin-sha256="testIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="; pin-sha256="r/testeEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="; pin-sha256="test2cbkZhZ82+JgmRUyGMoAeozA+BSXVXQWB8XWQ="; report-uri="http://abc.test.test/" |
action_result.data.\*.data.requests.\*.response.response.headers.referrer-policy | string | | no-referrer-when-downgrade |
action_result.data.\*.data.requests.\*.response.response.headers.report-to | string | | {"group":"ConsentUi","max_age":2592000,"endpoints":[{"url":"https://abc.test.test/csp/external"}]} |
action_result.data.\*.data.requests.\*.response.response.headers.server | string | | ESF |
action_result.data.\*.data.requests.\*.response.response.headers.set-cookie | string | | YSC=a-rkoUxJ3S4; Domain=.test.test; Path=/; Secure; HttpOnly; SameSite=none VISITOR_INFO1_LIVE=gH7gS_3ehDQ; Domain=.test.test; Expires=Wed, 25-Aug-2021 05:33:56 GMT; Path=/; Secure; HttpOnly; SameSite=none CONSENT=PENDING+007; expires=Fri, 01-Jan-2038 00:00:00 GMT; path=/; domain=.test.test |
action_result.data.\*.data.requests.\*.response.response.headers.status | string | | 200 |
action_result.data.\*.data.requests.\*.response.response.headers.strict-transport-security | string | | max-age=31536000 |
action_result.data.\*.data.requests.\*.response.response.headers.timing-allow-origin | string | | * |
action_result.data.\*.data.requests.\*.response.response.headers.vary | string | | Accept-Encoding |
action_result.data.\*.data.requests.\*.response.response.headers.via | string | | 1.1 73f3a231569992949c078c30859.test.test |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-cf-id | string | | 2fSWemgLL1daViXpR9QBZrtaZnsqQpggTXr_vB\_\_XSQqPkjy_r5Q== |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-cf-pop | string | | FRA53-C1 |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-id-2 | string | | ha+gqKNXBkV1gqr4AHswgx1OZSCdM7otKBZCL/JFLsojoWZn3VruarvQAhNV9ejI7FMh7PalI= |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-request-id | string | | 2KMY2R40Y5WJNG70 |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-server-side-encryption | string | | AES256 |
action_result.data.\*.data.requests.\*.response.response.headers.x-cache | string | | Hit from TestCloud |
action_result.data.\*.data.requests.\*.response.response.headers.x-content-type-options | string | | nosniff |
action_result.data.\*.data.requests.\*.response.response.headers.x-fb-content-md5 | string | `md5` | 0bd61dc947229e72968554f0c9fb51db |
action_result.data.\*.data.requests.\*.response.response.headers.x-fb-debug | string | | hUiq7Iq/Mt3plXYg3YAU6tS/1K06AainVmY+EU3e6s9L1+7n8CrQFf6Va+EHLQ2tSVCOePLr3hQ5PcEZ6c8R/Q== |
action_result.data.\*.data.requests.\*.response.response.headers.x-frame-options | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.response.response.headers.x-ua-compatible | string | | IE=edge, chrome=1 |
action_result.data.\*.data.requests.\*.response.response.headers.x-xss-protection | string | | 1; mode=block |
action_result.data.\*.data.requests.\*.response.response.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.response.response.protocol | string | `url` | http/1.1 |
action_result.data.\*.data.requests.\*.response.response.remoteIPAddress | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.response.remotePort | numeric | | 80 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.\* | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:authority | string | | abc.test.test |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:method | string | | GET |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:path | string | | / |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:scheme | string | `url` | https |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept | string | | text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept-Encoding | string | | gzip, deflate, br |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept-Language | string | | en-US |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Cache-Control | string | | no-cache |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Connection | string | | keep-alive |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Cookie | string | | B=dv5klk1g9hcet&b=3&s=t9; GUCS=AVkRFB1g |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Host | string | | abc.test.test |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Referer | string | | https://www.test.test/ |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Dest | string | | document |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Mode | string | | navigate |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-User | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Upgrade-Insecure-Requests | string | | 1 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.User-Agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.accept | string | | text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.accept-encoding | string | | gzip, deflate, br |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.accept-language | string | | en-US |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.cache-control | string | | no-cache |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.content-length | string | | 133 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.content-type | string | | application/x-www-form-urlencoded;charset=UTF-8 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.cookie | string | | CONSENT=PENDING+166 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.origin | string | `url` | https://abc.test.test |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.pragma | string | | no-cache |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.referer | string | `url` | https://abc.test.test/ |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-dest | string | | document |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-mode | string | | navigate |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-site | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-user | string | | ?1 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.upgrade-insecure-requests | string | | 1 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.user-agent | string | | TestBrowser/7.0 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.x-same-domain | string | `domain` | 1 |
action_result.data.\*.data.requests.\*.response.response.responseTime | numeric | | 1620619741627.715 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.certificateTransparencyCompliance | string | | unknown |
action_result.data.\*.data.requests.\*.response.response.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.response.response.securityDetails.issuer | string | | Test Authority |
action_result.data.\*.data.requests.\*.response.response.securityDetails.keyExchange | string | | ECDHE_RSA |
action_result.data.\*.data.requests.\*.response.response.securityDetails.keyExchangeGroup | string | | X25519 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.protocol | string | | TLS 1.2 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.sanList | string | | test.test |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.hashAlgorithm | string | | SHA-256 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.logDescription | string | | Test 'test' log |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.logId | string | `sha256` | A4B90990B418581487BB13A2CC67700A3C359804F91BDFB8E377CD0EC80DDC10 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.origin | string | | TLS extension |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.signatureAlgorithm | string | | ECDSA |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.signatureData | string | | 304502201B93510379EBD837E19EA9C684D5EF8D8E777A9A6D0B094AD30465C394FEFCEA0221008622A01AE4C1FDFA376F53FE0E9231E95E6FAE68E47559DA04F147E2461DC1C8 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.status | string | | Verified |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.timestamp | numeric | | 1500976811010 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.subjectName | string | | \*.apis.test.test |
action_result.data.\*.data.requests.\*.response.response.securityDetails.validFrom | numeric | | 1500972335 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.validTo | numeric | | 1508228880 |
action_result.data.\*.data.requests.\*.response.response.securityHeaders.\*.name | string | | Strict-Transport-Security |
action_result.data.\*.data.requests.\*.response.response.securityHeaders.\*.value | string | | max-age=31536000 |
action_result.data.\*.data.requests.\*.response.response.securityState | string | | neutral |
action_result.data.\*.data.requests.\*.response.response.status | numeric | | 200 |
action_result.data.\*.data.requests.\*.response.response.statusText | string | | OK |
action_result.data.\*.data.requests.\*.response.response.timing.connectEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.connectStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.dnsEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.dnsStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.proxyEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.proxyStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.pushEnd | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.response.timing.pushStart | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.response.timing.receiveHeadersEnd | numeric | | 229.759000241756 |
action_result.data.\*.data.requests.\*.response.response.timing.requestTime | numeric | | 25061896.019843 |
action_result.data.\*.data.requests.\*.response.response.timing.sendEnd | numeric | | 0.0940002501010895 |
action_result.data.\*.data.requests.\*.response.response.timing.sendStart | numeric | | 0.0710003077983856 |
action_result.data.\*.data.requests.\*.response.response.timing.sslEnd | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.sslStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.workerFetchStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.workerReady | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.workerRespondWithSettled | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.timing.workerStart | numeric | | -1 |
action_result.data.\*.data.requests.\*.response.response.url | string | `url` | http://test.test |
action_result.data.\*.data.requests.\*.response.size | numeric | | 48900 |
action_result.data.\*.data.requests.\*.response.type | string | | Document |
action_result.data.\*.data.timing.beginNavigation | string | | 2017-08-07T19:13:17.987Z |
action_result.data.\*.data.timing.domContentEventFired | string | | 2017-08-07T19:13:19.165Z |
action_result.data.\*.data.timing.frameNavigated | string | | 2017-08-07T19:13:19.897Z |
action_result.data.\*.data.timing.frameStartedLoading | string | | 2017-08-07T19:13:19.902Z |
action_result.data.\*.data.timing.frameStoppedLoading | string | | 2017-08-07T19:13:20.116Z |
action_result.data.\*.data.timing.loadEventFired | string | | 2017-08-07T19:13:19.897Z |
action_result.data.\*.description | string | | The submitted domain is on our blacklist. For your own safety we did not perform this scan... |
action_result.data.\*.fieldErrors.\*.location | string | | body |
action_result.data.\*.fieldErrors.\*.msg | string | | must be between 5 and 2083 characters |
action_result.data.\*.fieldErrors.\*.param | string | | |
action_result.data.\*.fieldErrors.\*.value | string | | 123 |
action_result.data.\*.lists.asns | string | | 32934 |
action_result.data.\*.lists.certificates.\*.issuer | string | | Test Authority |
action_result.data.\*.lists.certificates.\*.sanList | string | | test.test |
action_result.data.\*.lists.certificates.\*.subjectName | string | | \*.apis.test.test |
action_result.data.\*.lists.certificates.\*.validFrom | numeric | | 1500972335 |
action_result.data.\*.lists.certificates.\*.validTo | numeric | | 1508228880 |
action_result.data.\*.lists.countries | string | | IE |
action_result.data.\*.lists.domains | string | | accounts.test.test |
action_result.data.\*.lists.hashes | string | `sha256` | 548f2d6f4d0d820c6c5ffbeffcbd7f0e73193e2932eefe542accc84762deec87 |
action_result.data.\*.lists.ips | string | | 2a03:2880:f11c:8183:face:b00c:0:25de |
action_result.data.\*.lists.linkDomains | string | | test.test |
action_result.data.\*.lists.servers | string | | ESF |
action_result.data.\*.lists.urls | string | `url` | https://test.test |
action_result.data.\*.message | string | | Submission successful |
action_result.data.\*.meta.processors.abp.data.\*.source | string | | Test Authority |
action_result.data.\*.meta.processors.abp.data.\*.type | string | | annoyance |
action_result.data.\*.meta.processors.abp.data.\*.url | string | `url` | http://test.test |
action_result.data.\*.meta.processors.abp.state | string | | done |
action_result.data.\*.meta.processors.asn.data.\*.asn | string | | 43260 |
action_result.data.\*.meta.processors.asn.data.\*.country | string | | TR |
action_result.data.\*.meta.processors.asn.data.\*.date | string | | 2007-07-04 |
action_result.data.\*.meta.processors.asn.data.\*.description | string | | DGN, TR |
action_result.data.\*.meta.processors.asn.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.asn.data.\*.name | string | | DGN |
action_result.data.\*.meta.processors.asn.data.\*.registrar | string | | Test Authority |
action_result.data.\*.meta.processors.asn.data.\*.route | string | | 34.248.0.0/13 |
action_result.data.\*.meta.processors.asn.state | string | | done |
action_result.data.\*.meta.processors.cdnjs.data.\*.hash | string | `sha256` | 900b8e0052d80e532dcdca466e31b30d4f8eea58992ed9ff2b253d7d5346c811 |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches | string | | ckeditor/4.2/plugins/fakeobjects/images/spacer.gif |
action_result.data.\*.meta.processors.cdnjs.state | string | | done |
action_result.data.\*.meta.processors.done.data.state | string | | done |
action_result.data.\*.meta.processors.done.state | string | | done |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.area | numeric | | 1000 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.eu | string | | 1 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.range | numeric | | 780744703 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.timezone | string | | Europe/Dublin |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.geoip.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.geoip.state | string | | done |
action_result.data.\*.meta.processors.gsb.state | string | | done |
action_result.data.\*.meta.processors.rdns.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.rdns.data.\*.ptr | string | | abc.test.test |
action_result.data.\*.meta.processors.rdns.state | string | | done |
action_result.data.\*.meta.processors.wappa.state | string | | done |
action_result.data.\*.options.useragent | string | | TestBrowser/7.0 |
action_result.data.\*.page.asn | string | | AS43260 |
action_result.data.\*.page.asnname | string | | DGN, TR |
action_result.data.\*.page.city | string | | Bursa |
action_result.data.\*.page.country | string | | TR |
action_result.data.\*.page.domain | string | `domain` | www.test.test |
action_result.data.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.page.ptr | string | | abc.test.test |
action_result.data.\*.page.server | string | | TestServer/1.4 |
action_result.data.\*.page.url | string | `url` | http://test.test |
action_result.data.\*.result | string | `url` | https://urlscan.io/result/f04f2a29-d455-4830-874a-88191fb79352/ |
action_result.data.\*.stats.IPv6Percentage | numeric | | 75 |
action_result.data.\*.stats.adBlocked | numeric | | 2 |
action_result.data.\*.stats.domainStats.\*.count | numeric | | 55 |
action_result.data.\*.stats.domainStats.\*.countries | string | | IE |
action_result.data.\*.stats.domainStats.\*.domain | string | `domain` | www.test.test |
action_result.data.\*.stats.domainStats.\*.encodedSize | numeric | | 2042170 |
action_result.data.\*.stats.domainStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.domainStats.\*.initiators | string | | apis.test.test |
action_result.data.\*.stats.domainStats.\*.ips | string | | [2a03:2880:f006:21:face:b00c:0:3] |
action_result.data.\*.stats.domainStats.\*.redirects | numeric | | 0 |
action_result.data.\*.stats.domainStats.\*.size | numeric | | 2410398 |
action_result.data.\*.stats.ipStats.\*.asn.asn | string | | 43260 |
action_result.data.\*.stats.ipStats.\*.asn.country | string | | TR |
action_result.data.\*.stats.ipStats.\*.asn.date | string | | 2007-07-04 |
action_result.data.\*.stats.ipStats.\*.asn.description | string | | DGN, TR |
action_result.data.\*.stats.ipStats.\*.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.asn.name | string | | DGN |
action_result.data.\*.stats.ipStats.\*.asn.registrar | string | | ripencc |
action_result.data.\*.stats.ipStats.\*.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.stats.ipStats.\*.count | string | | |
action_result.data.\*.stats.ipStats.\*.countries | string | | IE |
action_result.data.\*.stats.ipStats.\*.domains | string | | www.test.test |
action_result.data.\*.stats.ipStats.\*.encodedSize | numeric | | 2042170 |
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
action_result.data.\*.stats.ipStats.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.ipv6 | boolean | | True False |
action_result.data.\*.stats.ipStats.\*.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.ipStats.\*.rdns.ptr | string | | abc.test.test |
action_result.data.\*.stats.ipStats.\*.redirects | numeric | | 3 |
action_result.data.\*.stats.ipStats.\*.requests | numeric | | 55 |
action_result.data.\*.stats.ipStats.\*.size | numeric | | 2410398 |
action_result.data.\*.stats.malicious | numeric | | 0 |
action_result.data.\*.stats.protocolStats.\*.count | numeric | | 55 |
action_result.data.\*.stats.protocolStats.\*.countries | string | | IE |
action_result.data.\*.stats.protocolStats.\*.encodedSize | numeric | | 2042170 |
action_result.data.\*.stats.protocolStats.\*.ips | string | | [2a03:2880:f11c:8183:face:b00c:0:25de] |
action_result.data.\*.stats.protocolStats.\*.protocol | string | `url` | http/1.1 |
action_result.data.\*.stats.protocolStats.\*.size | numeric | | 2410398 |
action_result.data.\*.stats.regDomainStats.\*.count | numeric | | 55 |
action_result.data.\*.stats.regDomainStats.\*.encodedSize | numeric | | 2042170 |
action_result.data.\*.stats.regDomainStats.\*.index | numeric | | 0 |
action_result.data.\*.stats.regDomainStats.\*.ips | string | | [2a03:2880:f006:21:face:b00c:0:3] |
action_result.data.\*.stats.regDomainStats.\*.redirects | numeric | | 4 |
action_result.data.\*.stats.regDomainStats.\*.regDomain | string | `domain` | test.test |
action_result.data.\*.stats.regDomainStats.\*.size | numeric | | 2410398 |
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.country | string | | GB |
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.domain | string | `domain` | apis |
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.failed | boolean | | True False |
action_result.data.\*.stats.resourceStats.\*.compression | string | | 1.0 |
action_result.data.\*.stats.resourceStats.\*.count | numeric | | 40 |
action_result.data.\*.stats.resourceStats.\*.countries | string | | TR |
action_result.data.\*.stats.resourceStats.\*.encodedSize | numeric | | 1876966 |
action_result.data.\*.stats.resourceStats.\*.ips | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.stats.resourceStats.\*.latency | numeric | | 0 |
action_result.data.\*.stats.resourceStats.\*.percentage | numeric | | 59 |
action_result.data.\*.stats.resourceStats.\*.size | numeric | | 1876925 |
action_result.data.\*.stats.resourceStats.\*.type | string | | Image |
action_result.data.\*.stats.securePercentage | numeric | | 10 |
action_result.data.\*.stats.secureRequests | numeric | | 7 |
action_result.data.\*.stats.serverStats.\*.count | numeric | | 55 |
action_result.data.\*.stats.serverStats.\*.countries | string | | IE |
action_result.data.\*.stats.serverStats.\*.encodedSize | numeric | | 2042170 |
action_result.data.\*.stats.serverStats.\*.ips | string | | [2a00:1450:4001:825::200e] |
action_result.data.\*.stats.serverStats.\*.server | string | | TestServer/1.4 |
action_result.data.\*.stats.serverStats.\*.size | numeric | | 2410398 |
action_result.data.\*.stats.tlsStats.\*.count | numeric | | 55 |
action_result.data.\*.stats.tlsStats.\*.countries | string | | IE |
action_result.data.\*.stats.tlsStats.\*.encodedSize | numeric | | 2042170 |
action_result.data.\*.stats.tlsStats.\*.ips | string | | [2a03:2880:f11c:8183:face:b00c:0:25de] |
action_result.data.\*.stats.tlsStats.\*.protocols.QUIC / / AES_128_GCM | numeric | | 9 |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_ECDSA / AES_128_GCM | numeric | | 2 |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / AES_128_GCM | numeric | | 5 |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_128_GCM | numeric | | 17 |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.3 / / AES_256_GCM | numeric | | 3 |
action_result.data.\*.stats.tlsStats.\*.securityState | string | | neutral |
action_result.data.\*.stats.tlsStats.\*.size | numeric | | 2410398 |
action_result.data.\*.stats.totalLinks | numeric | | 4 |
action_result.data.\*.stats.uniqCountries | numeric | | 2 |
action_result.data.\*.status | numeric | | 400 |
action_result.data.\*.submitter.country | string | | US |
action_result.data.\*.task.domURL | string | `url` | https://urlscan.io/dom/f04f2a29-d455-4830-874a-88191fb79352/ |
action_result.data.\*.task.method | string | | api |
action_result.data.\*.task.options.useragent | string | | TestBrowser/7.0 |
action_result.data.\*.task.reportURL | string | `url` | https://urlscan.io/result/f04f2a29-d455-4830-874a-88191fb79352/ |
action_result.data.\*.task.screenshotURL | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.task.source | string | | 4b0fb6d4 |
action_result.data.\*.task.time | string | | 2017-08-07T19:13:17.870Z |
action_result.data.\*.task.url | string | `url` | http://test.test |
action_result.data.\*.task.userAgent | string | | TestBrowser/7.0 |
action_result.data.\*.task.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.task.visibility | string | | public |
action_result.data.\*.url | string | `url` | abc.test.test |
action_result.data.\*.uuid | string | | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.verdicts.community.score | numeric | | 0 |
action_result.data.\*.verdicts.community.votesBenign | numeric | | 0 |
action_result.data.\*.verdicts.community.votesMalicious | numeric | | 0 |
action_result.data.\*.verdicts.community.votesTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.benignTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.enginesTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.maliciousTotal | numeric | | 0 |
action_result.data.\*.verdicts.engines.score | numeric | | 0 |
action_result.data.\*.verdicts.overall.hasVerdicts | numeric | | 0 |
action_result.data.\*.verdicts.overall.malicious | boolean | | False |
action_result.data.\*.verdicts.overall.score | numeric | | 0 |
action_result.data.\*.verdicts.urlscan.malicious | boolean | | False |
action_result.data.\*.verdicts.urlscan.score | numeric | | 0 |
action_result.data.\*.visibility | string | | public |
action_result.data.\*.data.console.\*.message.timestamp | numeric | | 1721648282157.842 |
action_result.data.\*.data.requests.\*.request.request.isSameSite | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.receiveHeadersStart | numeric | | 431.852 |
action_result.data.\*.data.requests.\*.request.redirectResponse.charset | string | | utf-8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.report-to | string | | {"group":"gws","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gws/other"}]} |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cross-origin-opener-policy | string | | same-origin-allow-popups; report-to="gws" |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-security-policy-report-only | string | | object-src 'none';base-uri 'self';script-src 'nonce-testtCZXDJBcDaS7euQg' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.encryptedClientHello | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.serverSignatureAlgorithm | numeric | | 1027 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logId | string | | TEST9994D5DB1ACEC55CB79DB4CD13A23287467CBCECDEC351485946711FB59B |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.origin | string | | Embedded in certificate |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.status | string | | Verified |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.timestamp | numeric | | 1719214546918 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.hashAlgorithm | string | | SHA-256 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureData | string | | TEST9999206F7183644269E6018A0FE1BC87492E448A594771A85180714B04E90ECF74CA29022100C46AC8249C2FBC02BC77162BCDA0D4C36A1F7D2210A8FA10F182A0D981E533E3 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logDescription | string | | Google 'Argon2024' log |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureAlgorithm | string | | ECDSA |
action_result.data.\*.data.requests.\*.request.redirectResponse.alternateProtocolUsage | string | | dnsTESTJobWonRace |
action_result.data.\*.data.requests.\*.request.redirectHasExtraInfo | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.request.isSameSite | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectHasExtraInfo | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.charset | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.alternateProtocolUsage | string | | TESTalternativeJobWonWithoutRace |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.receiveHeadersStart | numeric | | 431.852 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.report-to | string | | {"group":"gws","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gws/other"}]} |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cross-origin-opener-policy | string | | same-origin-allow-popups; report-to="gws" |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-security-policy-report-only | string | | object-src 'none';base-uri 'self';script-src 'nonce-TESTDATArztCZXDJBcDaS7euQg' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.encryptedClientHello | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.serverSignatureAlgorithm | numeric | | 1027 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logId | string | | TESTDATAD064D5DB1ACEC55CB79DB4CD13A23287467CBCECDEC351485946711FB59B |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.origin | string | | Embedded in certificate |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.status | string | | Verified |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.timestamp | numeric | | 1719214546918 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.hashAlgorithm | string | | SHA-256 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureData | string | | TESTDATA02206F7183644269E6018A0FE1BC87492E448A594771A85180714B04E90ECF74CA29022100C46AC8249C2FBC02BC77162BCDA0D4C36A1F7D2210A8FA10F182A0D981E533E3 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logDescription | string | | Google 'Argon2024' log |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureAlgorithm | string | | ECDSA |
action_result.data.\*.data.requests.\*.response.response.timing.receiveHeadersStart | numeric | | 557.51 |
action_result.data.\*.data.requests.\*.response.response.charset | string | | utf-8 |
action_result.data.\*.data.requests.\*.response.response.headers.accept-ch | string | | Sec-CH-UA-Platform Sec-CH-UA-Platform-Version Sec-CH-UA-Full-Version Sec-CH-UA-Arch Sec-CH-UA-Model Sec-CH-UA-Bitness Sec-CH-UA-Full-Version-List Sec-CH-UA-WoW64 |
action_result.data.\*.data.requests.\*.response.response.headers.permissions-policy | string | | unload=() |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-opener-policy | string | | same-origin-allow-popups; report-to="gws" |
action_result.data.\*.data.requests.\*.response.response.securityDetails.encryptedClientHello | boolean | | True False |
action_result.data.\*.data.requests.\*.response.response.securityDetails.serverSignatureAlgorithm | numeric | | 1027 |
action_result.data.\*.data.requests.\*.response.response.alternateProtocolUsage | string | | testdatadnsnH3JobWonRace |
action_result.data.\*.data.requests.\*.response.hasExtraInfo | boolean | | True False |
action_result.data.\*.data.requests.\*.request.request.isLinkPreload | boolean | | True False |
action_result.data.\*.data.requests.\*.response.response.headers.version | string | | 652602471 |
action_result.data.\*.data.requests.\*.request.request.headers.Accept | string | | \*/\* |
action_result.data.\*.data.requests.\*.request.request.headers.Sec-Fetch-Mode | string | | cors |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Request-Method | string | | POST |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Request-Headers | string | | content-type,x-goog-api-key,x-user-agent |
action_result.data.\*.data.requests.\*.request.initiator.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.response.response.headers.server-timing | string | | gfet4t7; dur=12 |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-max-age | string | | 3600 |
action_result.data.\*.data.requests.\*.request.request.headers.X-User-Agent | string | | grpc-web-javascript/0.1 |
action_result.data.\*.data.requests.\*.request.request.headers.X-Goog-Api-Key | string | | TESTDATAyCbsbvGCe7C9mCtdaTycZB2eUFuzsYKG_E |
action_result.data.\*.meta.processors.umbrella.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.umbrella.data.\*.hostname | string | | www.google.com |
action_result.data.\*.page.title | string | | Google |
action_result.data.\*.page.status | string | | 200 |
action_result.data.\*.page.mimeType | string | | text/html |
action_result.data.\*.page.tlsIssuer | string | | WR2 |
action_result.data.\*.page.apexDomain | string | | google.com |
action_result.data.\*.page.redirected | string | | sub-domain |
action_result.data.\*.page.tlsAgeDays | numeric | | 28 |
action_result.data.\*.page.tlsValidDays | numeric | | 83 |
action_result.data.\*.page.tlsValidFrom | string | | 2024-06-24T06:35:44.000Z |
action_result.data.\*.page.umbrellaRank | numeric | | 10 |
action_result.data.\*.task.domain | string | | google.com |
action_result.data.\*.task.apexDomain | string | | google.com |
action_result.data.\*.scanner.country | string | | us |
action_result.data.\*.verdicts.engines.malicious | boolean | | True False |
action_result.data.\*.verdicts.urlscan.hasVerdicts | boolean | | True False |
action_result.data.\*.verdicts.community.malicious | boolean | | True False |
action_result.data.\*.verdicts.community.hasVerdicts | boolean | | True False |
action_result.summary.added_tags_num | numeric | | |
action_result.data.\*.data.cookies.\*.partitionKey | string | | https://watermelongame.com |
action_result.data.\*.data.requests.\*.response.response.headers.nel | string | | {"success_fraction":0,"report_to":"cf-nel","max_age":604800} |
action_result.data.\*.data.requests.\*.response.response.headers.cf-ray | string | | 8a73b0909a9e975f-FRA |
action_result.data.\*.data.requests.\*.response.response.headers.x-robots-tag | string | | noindex |
action_result.data.\*.data.requests.\*.response.response.headers.cf-cache-status | string | | HIT |
action_result.data.\*.data.requests.\*.response.response.headers.x-middleton-display | string | | sol-js |
action_result.data.\*.data.requests.\*.request.request.urlFragment | string | | #property=65a4000db492fb00132dcf7e&product=sop |
action_result.data.\*.data.requests.\*.response.response.headers.edge-control | string | | cache-maxage=60m,downstream-ttl=60m |
action_result.data.\*.data.requests.\*.response.response.headers.x-sol | string | | middleton |
action_result.data.\*.data.requests.\*.response.response.headers.display | string | | staticcontent_sol |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-version-id | string | | r5.lR.LJ66XEXzxUUVo7iMemjL_F_GoE |
action_result.data.\*.data.requests.\*.request.request.headers.X-PINGBACK | string | | pingpong |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.vary | string | | Accept-Encoding |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cf-ray | string | | 8a73b0aa69498dd7-HEL |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.vary | string | | Accept-Encoding |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cf-ray | string | | 8a73b0aa69498dd7-HEL |
action_result.data.\*.data.requests.\*.response.response.headers.cf-bgj | string | | minify |
action_result.data.\*.data.requests.\*.response.response.headers.apigw-requestid | string | | bUMp6iOMoAMEbPQ= |
action_result.data.\*.data.requests.\*.response.response.headers.server-processing-duration-in-ticks | string | | 154170 |
action_result.data.\*.data.requests.\*.request.request.headers.content-type | string | | text/plain |
action_result.data.\*.data.requests.\*.response.response.headers.allow | string | | POST, OPTIONS, GET |
action_result.data.\*.data.requests.\*.response.failed.corsErrorStatus.corsError | string | | MissingAllowOriginHeader |
action_result.data.\*.data.requests.\*.response.failed.corsErrorStatus.failedParameter | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-server | string | | 10.45.18.91 |
action_result.data.\*.data.requests.\*.response.response.headers.debug | string | | NON-OPTIONS |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-hash | string | | crc32c=cpEfJQ==, md5=rUsPYG4PhGW8TEwXCzfhow== |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-generation | string | | 1620242732037093 |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-storage-class | string | | MULTI_REGIONAL |
action_result.data.\*.data.requests.\*.response.response.headers.x-guploader-uploadid | string | | ABPtcPovIz6nZtqULu9hGQBSVbC6_z8lEyamrIA64gM0CArHcTLURzj7EtelAkaCkOXM4KyL70M |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-metageneration | string | | 5 |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-stored-content-length | string | | 43 |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-stored-content-encoding | string | | identity |
action_result.data.\*.data.requests.\*.response.response.headers.X-Robots-Tag | string | | noindex |
action_result.data.\*.data.requests.\*.response.response.headers.Permissions-Policy | string | | browsing-topics=() |
action_result.data.\*.data.requests.\*.response.response.headers.x-nbr | string | | 1 |
action_result.data.\*.data.requests.\*.response.response.headers.x-envoy-upstream-service-time | string | | 0 |
action_result.data.\*.data.requests.\*.response.response.headers.observe-browsing-topics | string | | ?1 |
action_result.data.\*.data.requests.\*.response.response.headers.google-creative-id | string | | -2 |
action_result.data.\*.data.requests.\*.response.response.headers.google-lineitem-id | string | | -2 |
action_result.data.\*.data.requests.\*.response.response.headers.google-mediationtag-id | string | | -2 |
action_result.data.\*.data.requests.\*.response.response.headers.google-mediationgroup-id | string | | -2 |
action_result.data.\*.data.requests.\*.response.response.headers.x-cache-status | string | | HIT |
action_result.data.\*.data.requests.\*.response.response.headers.x-rgw-object-type | string | | Normal |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-mnet-hl2 | string | | E |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-mnet-hl2 | string | | E |
action_result.data.\*.data.requests.\*.response.response.headers.x-mnet-hl2 | string | | E |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-embedder-policy | string | | require-corp |
action_result.data.\*.data.requests.\*.response.response.headers.cf-polished | string | | origSize=1018 |
action_result.data.\*.meta.processors.wappa.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.wappa.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.wappa.data.\*.website | string | | https://getbootstrap.com |
action_result.data.\*.meta.processors.wappa.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.wappa.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.wappa.data.\*.confidence.\*.pattern | string | | bootstrap(?:[^>]\*?([0-9a-fA-F]{7,40}|[\\d]+(?:.[\\d]+(?:.[\\d]+)?)?)|)[^>]\*?(?:\\.min)?\\.js |
action_result.data.\*.meta.processors.wappa.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.wappa.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.stats.tlsStats.\*.protocols.TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305 | numeric | | 127 |
action_result.summary | string | | |
action_result.message | string | | Successfully retrieved information |
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
action_result.status | string | | success failed |
action_result.parameter.report_id | string | `urlscan submission id` | |
action_result.summary.id | numeric | | 722 |
action_result.summary.name | string | | cf9412df-963e-46a2-849b-de693d055b7b.png |
action_result.summary.size | numeric | | 13841 |
action_result.summary.vault_id | string | | 0599692c5298dd88f731960c55299f8de3331cf1 |
action_result.summary.file_type | string | | image/png |
action_result.summary.container_id | numeric | | 2390 |
action_result.message | string | | Successfully retrieved information |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.parameter.container_id | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
