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
action_result.data.\*.data.requests.\*.initiatorInfo.columnNumber | numeric | | 88 |
action_result.data.\*.data.requests.\*.initiatorInfo.host | string | | www.google.com |
action_result.data.\*.data.requests.\*.initiatorInfo.lineNumber | numeric | | 27 |
action_result.data.\*.data.requests.\*.initiatorInfo.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.initiatorInfo.stack.callFrames.\*.columnNumber | numeric | | 386 |
action_result.data.\*.data.requests.\*.initiatorInfo.stack.callFrames.\*.functionName | string | | lb |
action_result.data.\*.data.requests.\*.initiatorInfo.stack.callFrames.\*.lineNumber | numeric | | 13 |
action_result.data.\*.data.requests.\*.initiatorInfo.stack.callFrames.\*.scriptId | string | | 40 |
action_result.data.\*.data.requests.\*.initiatorInfo.stack.callFrames.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.initiatorInfo.type | string | | parser |
action_result.data.\*.data.requests.\*.initiatorInfo.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.documentURL | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.frameId | string | | frame |
action_result.data.\*.data.requests.\*.request.hasUserGesture | boolean | | True False |
action_result.data.\*.data.requests.\*.request.initiator.columnNumber | numeric | | 88 |
action_result.data.\*.data.requests.\*.request.initiator.host | string | | www.google.com |
action_result.data.\*.data.requests.\*.request.initiator.lineNumber | numeric | | 27 |
action_result.data.\*.data.requests.\*.request.initiator.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.columnNumber | numeric | | 386 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.functionName | string | | lb |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.lineNumber | numeric | | 13 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.scriptId | string | | 40 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.initiator.type | string | | parser |
action_result.data.\*.data.requests.\*.request.initiator.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.loaderId | string | | loader |
action_result.data.\*.data.requests.\*.request.primaryRequest | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectHasExtraInfo | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.alternateProtocolUsage | string | | unspecifiedReason |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.asn | string | | 43260 |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.country | string | | TR |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.date | string | | 2007-07-04 |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.description | string | | DGN, TR |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.name | string | | DGN |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.registrar | string | | ripencc |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.data.requests.\*.request.redirectResponse.charset | string | | utf-8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.encodedDataLength | numeric | | 1024 |
action_result.data.\*.data.requests.\*.request.redirectResponse.fromDiskCache | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.fromPrefetchCache | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.fromServiceWorker | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.area | numeric | | 100 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.city | string | | Bursa |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.country | string | | TR |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.country_name | string | | Turkey |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.eu | string | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.ll | numeric | | -8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.range | numeric | | 1167286271 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.region | string | | 16 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.timezone | string | | Europe/London |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.zip | numeric | | 16245 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.\* | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Accept | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.accept-ch | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Accept-Ranges | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.accept-ranges | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-credentials | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Allow-Credentials | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Allow-Headers | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-headers | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-method | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Allow-Methods | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-methods | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-origin | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Expose-Headers | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-expose-headers | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Max-Age | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-max-age | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Request-Headers | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Request-Method | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Age | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.age | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.allow | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.alt-svc | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Alt-Svc | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.apigw-requestid | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.ats-carp-promotion | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cache-control | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cf-bgj | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cf-cache-status | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cf-polished | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cf-ray | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Connection | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-disposition | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Language | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-language | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Length | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-length | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-md5 | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Security-Policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-security-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-security-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Security-Policy-Report-Only | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Type | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-type | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cross-origin-embedder-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cross-origin-opener-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cross-origin-opener-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cross-origin-resource-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Date | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.date | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.debug | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.display | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.edge-control | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.ETag | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Etag | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.etag | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.expect-ct | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Expect-CT | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.expires | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Expires | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.google-creative-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.google-lineitem-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.google-mediationgroup-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.google-mediationtag-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Keep-Alive | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Last-Modified | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.last-modified | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.link | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Location | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.location | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.nel | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Non-Authoritative-Reason | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.observe-browsing-topics | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Origin | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.p3p | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.P3P | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.permissions-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Permissions-Policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.pragma | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Pragma | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.public-key-pins-report-only | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Referer | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.referrer-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Referrer-Policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.report-to | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Server | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.server | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.server-processing-duration-in-ticks | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.server-timing | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.set-cookie | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Set-Cookie | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.status | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Strict-Transport-Security | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.strict-transport-security | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.timing-allow-origin | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Timing-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Transfer-Encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Upgrade | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.User-Agent | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.vary | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Vary | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.version | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Via | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.via | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Amz-Cf-Id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-cf-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Amz-Cf-Pop | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-cf-pop | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-id-2 | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-request-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-server-side-encryption | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-version-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Cache | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-cache | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-cache-status | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-content-type-options | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Content-Type-Options | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-DIS-Request-ID | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-envoy-upstream-service-time | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-fb-content-md5 | string | `md5` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-fb-debug | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-frame-options | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Frame-Options | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Goog-Api-Key | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-generation | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-hash | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-metageneration | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-storage-class | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-stored-content-encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-stored-content-length | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-guploader-uploadid | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-LLID | string | `md5` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-middleton-display | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-mnet-hl2 | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-nbr | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-PINGBACK | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Powered-By | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-rgw-object-type | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Robots-Tag | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-robots-tag | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Same-Domain | string | `domain` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-server | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-sol | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-ua-compatible | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-User-Agent | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-xss-protection | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-XSS-Protection | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headersText | string | | HTTP/1.1 200 OK |
action_result.data.\*.data.requests.\*.request.redirectResponse.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.request.redirectResponse.protocol | string | | h2 |
action_result.data.\*.data.requests.\*.request.redirectResponse.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.rdns.ptr | string | | dns.google |
action_result.data.\*.data.requests.\*.request.redirectResponse.remoteIPAddress | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.remotePort | numeric | | 443 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.\* | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:authority | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:method | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:path | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:scheme | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.accept | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept-Encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.accept-encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept-Language | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.accept-language | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.cache-control | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Connection | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.content-length | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.content-type | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Cookie | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.cookie | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Host | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.origin | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Pragma | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.pragma | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Referer | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.referer | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Dest | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-dest | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-mode | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-site | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-User | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-user | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.upgrade-insecure-requests | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.User-Agent | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.user-agent | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.x-same-domain | string | `domain` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeadersText | string | | GET / HTTP/1.1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.responseTime | numeric | | 1721648282000 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.certificateTransparencyCompliance | string | | compliant |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.encryptedClientHello | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.issuer | string | | WR2 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.keyExchange | string | | ECDHE_RSA |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.keyExchangeGroup | string | | X25519 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.protocol | string | | TLS 1.3 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.sanList.\* | string | | ['www.google.com'] |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.serverSignatureAlgorithm | numeric | | 1027 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.hashAlgorithm | string | | SHA-256 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logDescription | string | | Google 'Xenon2024h1' log |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logId | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.origin | string | | Embedded in certificate |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureAlgorithm | string | | ECDSA |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureData | string | | 3045022100 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.status | string | | Verified |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.timestamp | numeric | | 1719210944000 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.subjectName | string | | www.google.com |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.validFrom | numeric | | 1719210944 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.validTo | numeric | | 1726468544 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityHeaders.\*.name | string | | x-frame-options |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityHeaders.\*.value | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityState | string | | secure |
action_result.data.\*.data.requests.\*.request.redirectResponse.serviceWorkerResponseSource | string | | network |
action_result.data.\*.data.requests.\*.request.redirectResponse.status | numeric | | 200 |
action_result.data.\*.data.requests.\*.request.redirectResponse.statusText | string | | OK |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.connectEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.connectStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.dnsEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.dnsStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.proxyEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.proxyStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.pushEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.pushStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.receiveHeadersEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.receiveHeadersStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.requestTime | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sendEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sendStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sslEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sslStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerFetchStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerReady | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerRespondWithSettled | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.request.headers.\* | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Accept | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.accept-ch | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Accept-Ranges | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.accept-ranges | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-allow-credentials | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Allow-Credentials | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Allow-Headers | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-allow-headers | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-allow-method | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Allow-Methods | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-allow-methods | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-allow-origin | string | `url` | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Expose-Headers | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-expose-headers | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Max-Age | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-max-age | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Request-Headers | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Request-Method | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Age | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.age | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.allow | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.alt-svc | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Alt-Svc | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.apigw-requestid | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.ats-carp-promotion | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cache-control | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cf-bgj | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cf-cache-status | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cf-polished | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cf-ray | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Connection | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-disposition | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Encoding | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-encoding | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Language | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-language | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Length | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-length | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-md5 | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Security-Policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-security-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-security-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Security-Policy-Report-Only | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Type | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-type | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cross-origin-embedder-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cross-origin-opener-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cross-origin-opener-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cross-origin-resource-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Date | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.date | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.debug | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.display | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.edge-control | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.ETag | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Etag | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.etag | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.expect-ct | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Expect-CT | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.expires | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Expires | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.google-creative-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.google-lineitem-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.google-mediationgroup-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.google-mediationtag-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Keep-Alive | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Last-Modified | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.last-modified | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.link | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Location | string | `url` | |
action_result.data.\*.data.requests.\*.request.request.headers.location | string | `url` | |
action_result.data.\*.data.requests.\*.request.request.headers.nel | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Non-Authoritative-Reason | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.observe-browsing-topics | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Origin | string | `url` | |
action_result.data.\*.data.requests.\*.request.request.headers.p3p | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.P3P | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.permissions-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Permissions-Policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.pragma | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Pragma | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.public-key-pins-report-only | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Referer | string | `url` | |
action_result.data.\*.data.requests.\*.request.request.headers.referrer-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Referrer-Policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.report-to | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Server | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.server | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.server-processing-duration-in-ticks | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.server-timing | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.set-cookie | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Set-Cookie | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.status | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Strict-Transport-Security | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.strict-transport-security | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.timing-allow-origin | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Timing-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Transfer-Encoding | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Upgrade | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.User-Agent | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.vary | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Vary | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.version | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Via | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.via | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Amz-Cf-Id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-cf-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Amz-Cf-Pop | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-cf-pop | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-id-2 | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-request-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-server-side-encryption | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-version-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Cache | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-cache | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-cache-status | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-content-type-options | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Content-Type-Options | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-DIS-Request-ID | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-envoy-upstream-service-time | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-fb-content-md5 | string | `md5` | |
action_result.data.\*.data.requests.\*.request.request.headers.x-fb-debug | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-frame-options | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Frame-Options | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Goog-Api-Key | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-generation | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-hash | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-metageneration | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-storage-class | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-stored-content-encoding | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-stored-content-length | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-guploader-uploadid | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-LLID | string | `md5` | |
action_result.data.\*.data.requests.\*.request.request.headers.x-middleton-display | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-mnet-hl2 | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-nbr | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-PINGBACK | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Powered-By | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-rgw-object-type | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Robots-Tag | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-robots-tag | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Same-Domain | string | `domain` | |
action_result.data.\*.data.requests.\*.request.request.headers.x-server | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-sol | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-ua-compatible | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-User-Agent | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-xss-protection | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-XSS-Protection | string | | |
action_result.data.\*.data.requests.\*.request.request.hasPostData | boolean | | True False |
action_result.data.\*.data.requests.\*.request.request.initialPriority | string | | VeryHigh |
action_result.data.\*.data.requests.\*.request.request.isLinkPreload | boolean | | True False |
action_result.data.\*.data.requests.\*.request.request.isSameSite | boolean | | True False |
action_result.data.\*.data.requests.\*.request.request.method | string | | GET |
action_result.data.\*.data.requests.\*.request.request.mixedContentType | string | | none |
action_result.data.\*.data.requests.\*.request.request.postData | string | | |
action_result.data.\*.data.requests.\*.request.request.postDataEntries.\*.bytes | string | | payload |
action_result.data.\*.data.requests.\*.request.request.referrerPolicy | string | | strict-origin-when-cross-origin |
action_result.data.\*.data.requests.\*.request.request.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.request.urlFragment | string | | fragment |
action_result.data.\*.data.requests.\*.request.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.request.timestamp | numeric | | 1721648282 |
action_result.data.\*.data.requests.\*.request.type | string | | Document |
action_result.data.\*.data.requests.\*.request.wallTime | numeric | | 1721648282 |
action_result.data.\*.data.requests.\*.requests.\*.documentURL | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.frameId | string | | frame |
action_result.data.\*.data.requests.\*.requests.\*.hasUserGesture | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.initiator.columnNumber | numeric | | 88 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.host | string | | www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.initiator.lineNumber | numeric | | 27 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.columnNumber | numeric | | 386 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.functionName | string | | lb |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.lineNumber | numeric | | 13 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.scriptId | string | | 40 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.initiator.type | string | | parser |
action_result.data.\*.data.requests.\*.requests.\*.initiator.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.loaderId | string | | loader |
action_result.data.\*.data.requests.\*.requests.\*.primaryRequest | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectHasExtraInfo | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.alternateProtocolUsage | string | | unspecifiedReason |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.asn | string | | 43260 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.country | string | | TR |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.date | string | | 2007-07-04 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.description | string | | DGN, TR |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.name | string | | DGN |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.registrar | string | | ripencc |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.charset | string | | utf-8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.encodedDataLength | numeric | | 1024 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.fromDiskCache | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.fromPrefetchCache | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.fromServiceWorker | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.area | numeric | | 100 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.city | string | | Bursa |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.country | string | | TR |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.country_name | string | | Turkey |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.eu | string | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.ll | numeric | | -8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.range | numeric | | 1167286271 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.region | string | | 16 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.timezone | string | | Europe/London |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.zip | numeric | | 16245 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.\* | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Accept | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.accept-ch | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Accept-Ranges | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.accept-ranges | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-credentials | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Allow-Credentials | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Allow-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-method | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Allow-Methods | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-methods | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-origin | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Expose-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-expose-headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Max-Age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-max-age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Request-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Request-Method | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.allow | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.alt-svc | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Alt-Svc | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.apigw-requestid | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.ats-carp-promotion | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cache-control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cf-bgj | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cf-cache-status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cf-polished | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cf-ray | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Connection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-disposition | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-md5 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Security-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-security-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-security-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Security-Policy-Report-Only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cross-origin-embedder-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cross-origin-opener-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cross-origin-opener-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cross-origin-resource-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Date | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.date | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.debug | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.display | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.edge-control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.ETag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Etag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.etag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.expect-ct | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Expect-CT | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.expires | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Expires | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.google-creative-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.google-lineitem-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.google-mediationgroup-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.google-mediationtag-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Keep-Alive | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Last-Modified | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.last-modified | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.link | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Location | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.location | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.nel | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Non-Authoritative-Reason | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.observe-browsing-topics | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Origin | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.p3p | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.P3P | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.permissions-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Permissions-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.public-key-pins-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Referer | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.referrer-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Referrer-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.report-to | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.server-processing-duration-in-ticks | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.server-timing | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.set-cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Set-Cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Strict-Transport-Security | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.strict-transport-security | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.timing-allow-origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Timing-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Transfer-Encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Upgrade | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.User-Agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.vary | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Vary | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.version | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Via | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.via | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Amz-Cf-Id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-cf-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Amz-Cf-Pop | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-cf-pop | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-id-2 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-request-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-server-side-encryption | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-version-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Cache | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-cache | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-cache-status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-content-type-options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Content-Type-Options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-DIS-Request-ID | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-envoy-upstream-service-time | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-fb-content-md5 | string | `md5` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-fb-debug | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-frame-options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Frame-Options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Goog-Api-Key | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-generation | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-hash | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-metageneration | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-storage-class | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-stored-content-encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-stored-content-length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-guploader-uploadid | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-LLID | string | `md5` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-middleton-display | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-mnet-hl2 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-nbr | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-PINGBACK | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Powered-By | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-rgw-object-type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Robots-Tag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-robots-tag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Same-Domain | string | `domain` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-sol | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-ua-compatible | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-User-Agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-xss-protection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-XSS-Protection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headersText | string | | HTTP/1.1 200 OK |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.protocol | string | | h2 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.rdns.ptr | string | | dns.google |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.remoteIPAddress | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.remotePort | numeric | | 443 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.\* | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:authority | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:method | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:path | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:scheme | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept-Encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept-encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept-Language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept-language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.cache-control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Connection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.content-length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.content-type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Host | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.origin | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Referer | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.referer | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Dest | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-dest | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-mode | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-site | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-User | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-user | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.upgrade-insecure-requests | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.User-Agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.user-agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.x-same-domain | string | `domain` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeadersText | string | | GET / HTTP/1.1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.responseTime | numeric | | 1721648282000 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.certificateTransparencyCompliance | string | | compliant |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.encryptedClientHello | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.issuer | string | | WR2 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.keyExchange | string | | ECDHE_RSA |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.keyExchangeGroup | string | | X25519 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.protocol | string | | TLS 1.3 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.sanList.\* | string | | ['www.google.com'] |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.serverSignatureAlgorithm | numeric | | 1027 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.hashAlgorithm | string | | SHA-256 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logDescription | string | | Google 'Xenon2024h1' log |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logId | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.origin | string | | Embedded in certificate |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureAlgorithm | string | | ECDSA |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureData | string | | 3045022100 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.status | string | | Verified |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.timestamp | numeric | | 1719210944000 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.subjectName | string | | www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.validFrom | numeric | | 1719210944 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.validTo | numeric | | 1726468544 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityHeaders.\*.name | string | | x-frame-options |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityHeaders.\*.value | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityState | string | | secure |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.serviceWorkerResponseSource | string | | network |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.status | numeric | | 200 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.statusText | string | | OK |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.connectEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.connectStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.dnsEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.dnsStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.proxyEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.proxyStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.pushEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.pushStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.receiveHeadersEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.receiveHeadersStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.requestTime | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sendEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sendStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sslEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sslStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerFetchStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerReady | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerRespondWithSettled | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.\* | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Accept | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.accept-ch | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Accept-Ranges | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.accept-ranges | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-allow-credentials | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Allow-Credentials | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Allow-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-allow-headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-allow-method | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Allow-Methods | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-allow-methods | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-allow-origin | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Expose-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-expose-headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Max-Age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-max-age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Request-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Request-Method | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.allow | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.alt-svc | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Alt-Svc | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.apigw-requestid | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.ats-carp-promotion | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cache-control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cf-bgj | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cf-cache-status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cf-polished | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cf-ray | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Connection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-disposition | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-md5 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Security-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-security-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-security-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Security-Policy-Report-Only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cross-origin-embedder-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cross-origin-opener-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cross-origin-opener-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cross-origin-resource-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Date | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.date | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.debug | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.display | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.edge-control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.ETag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Etag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.etag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.expect-ct | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Expect-CT | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.expires | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Expires | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.google-creative-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.google-lineitem-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.google-mediationgroup-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.google-mediationtag-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Keep-Alive | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Last-Modified | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.last-modified | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.link | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Location | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.location | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.nel | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Non-Authoritative-Reason | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.observe-browsing-topics | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Origin | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.p3p | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.P3P | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.permissions-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Permissions-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.public-key-pins-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Referer | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.referrer-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Referrer-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.report-to | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.server-processing-duration-in-ticks | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.server-timing | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.set-cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Set-Cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Strict-Transport-Security | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.strict-transport-security | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.timing-allow-origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Timing-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Transfer-Encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Upgrade | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.User-Agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.vary | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Vary | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.version | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Via | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.via | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Amz-Cf-Id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-cf-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Amz-Cf-Pop | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-cf-pop | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-id-2 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-request-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-server-side-encryption | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-version-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Cache | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-cache | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-cache-status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-content-type-options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Content-Type-Options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-DIS-Request-ID | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-envoy-upstream-service-time | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-fb-content-md5 | string | `md5` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-fb-debug | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-frame-options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Frame-Options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Goog-Api-Key | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-generation | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-hash | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-metageneration | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-storage-class | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-stored-content-encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-stored-content-length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-guploader-uploadid | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-LLID | string | `md5` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-middleton-display | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-mnet-hl2 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-nbr | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-PINGBACK | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Powered-By | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-rgw-object-type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Robots-Tag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-robots-tag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Same-Domain | string | `domain` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-sol | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-ua-compatible | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-User-Agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-xss-protection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-XSS-Protection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.hasPostData | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.request.initialPriority | string | | VeryHigh |
action_result.data.\*.data.requests.\*.requests.\*.request.isLinkPreload | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.request.isSameSite | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.request.method | string | | GET |
action_result.data.\*.data.requests.\*.requests.\*.request.mixedContentType | string | | none |
action_result.data.\*.data.requests.\*.requests.\*.request.postData | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.postDataEntries.\*.bytes | string | | payload |
action_result.data.\*.data.requests.\*.requests.\*.request.referrerPolicy | string | | strict-origin-when-cross-origin |
action_result.data.\*.data.requests.\*.requests.\*.request.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.request.urlFragment | string | | fragment |
action_result.data.\*.data.requests.\*.requests.\*.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.requests.\*.timestamp | numeric | | 1721648282 |
action_result.data.\*.data.requests.\*.requests.\*.type | string | | Document |
action_result.data.\*.data.requests.\*.requests.\*.wallTime | numeric | | 1721648282 |
action_result.data.\*.data.requests.\*.response.abp.source | string | | abp |
action_result.data.\*.data.requests.\*.response.abp.type | string | | Document |
action_result.data.\*.data.requests.\*.response.abp.url | string | `url` | https://example.com |
action_result.data.\*.data.requests.\*.response.asn.asn | string | | 43260 |
action_result.data.\*.data.requests.\*.response.asn.country | string | | TR |
action_result.data.\*.data.requests.\*.response.asn.date | string | | 2007-07-04 |
action_result.data.\*.data.requests.\*.response.asn.description | string | | DGN, TR |
action_result.data.\*.data.requests.\*.response.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.asn.name | string | | DGN |
action_result.data.\*.data.requests.\*.response.asn.registrar | string | | ripencc |
action_result.data.\*.data.requests.\*.response.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.data.requests.\*.response.dataLength | numeric | | 1024 |
action_result.data.\*.data.requests.\*.response.encodedDataLength | numeric | | 1024 |
action_result.data.\*.data.requests.\*.response.failed.blockedReason | string | | mixed-content |
action_result.data.\*.data.requests.\*.response.failed.canceled | boolean | | True False |
action_result.data.\*.data.requests.\*.response.failed.corsErrorStatus.corsError | string | | MissingAllowOriginHeader |
action_result.data.\*.data.requests.\*.response.failed.corsErrorStatus.failedParameter | string | | |
action_result.data.\*.data.requests.\*.response.failed.errorText | string | | net::ERR_FAILED |
action_result.data.\*.data.requests.\*.response.failed.requestId | string | | 24696.156 |
action_result.data.\*.data.requests.\*.response.failed.timestamp | numeric | | 25061896.916161 |
action_result.data.\*.data.requests.\*.response.failed.type | string | | Document |
action_result.data.\*.data.requests.\*.response.geoip.area | numeric | | 100 |
action_result.data.\*.data.requests.\*.response.geoip.city | string | | Bursa |
action_result.data.\*.data.requests.\*.response.geoip.country | string | | TR |
action_result.data.\*.data.requests.\*.response.geoip.country_name | string | | Turkey |
action_result.data.\*.data.requests.\*.response.geoip.eu | string | | 0 |
action_result.data.\*.data.requests.\*.response.geoip.ll | numeric | | -8 |
action_result.data.\*.data.requests.\*.response.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.geoip.range | numeric | | 1167286271 |
action_result.data.\*.data.requests.\*.response.geoip.region | string | | 16 |
action_result.data.\*.data.requests.\*.response.geoip.timezone | string | | Europe/London |
action_result.data.\*.data.requests.\*.response.geoip.zip | numeric | | 16245 |
action_result.data.\*.data.requests.\*.response.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.file | string | | jquery.js |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.project | string | | jquery |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.source | string | | cdnjs |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.data.requests.\*.response.hasExtraInfo | boolean | | True False |
action_result.data.\*.data.requests.\*.response.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.rdns.ptr | string | | dns.google |
action_result.data.\*.data.requests.\*.response.requestId | string | | 24696.156 |
action_result.data.\*.data.requests.\*.response.size | numeric | | 1024 |
action_result.data.\*.data.requests.\*.response.type | string | | Document |
action_result.data.\*.data.requests.\*.response.response.alternateProtocolUsage | string | | unspecifiedReason |
action_result.data.\*.data.requests.\*.response.response.asn.asn | string | | 43260 |
action_result.data.\*.data.requests.\*.response.response.asn.country | string | | TR |
action_result.data.\*.data.requests.\*.response.response.asn.date | string | | 2007-07-04 |
action_result.data.\*.data.requests.\*.response.response.asn.description | string | | DGN, TR |
action_result.data.\*.data.requests.\*.response.response.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.response.asn.name | string | | DGN |
action_result.data.\*.data.requests.\*.response.response.asn.registrar | string | | ripencc |
action_result.data.\*.data.requests.\*.response.response.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.data.requests.\*.response.response.charset | string | | utf-8 |
action_result.data.\*.data.requests.\*.response.response.encodedDataLength | numeric | | 1024 |
action_result.data.\*.data.requests.\*.response.response.fromDiskCache | boolean | | True False |
action_result.data.\*.data.requests.\*.response.response.fromPrefetchCache | boolean | | True False |
action_result.data.\*.data.requests.\*.response.response.fromServiceWorker | boolean | | True False |
action_result.data.\*.data.requests.\*.response.response.geoip.area | numeric | | 100 |
action_result.data.\*.data.requests.\*.response.response.geoip.city | string | | Bursa |
action_result.data.\*.data.requests.\*.response.response.geoip.country | string | | TR |
action_result.data.\*.data.requests.\*.response.response.geoip.country_name | string | | Turkey |
action_result.data.\*.data.requests.\*.response.response.geoip.eu | string | | 0 |
action_result.data.\*.data.requests.\*.response.response.geoip.ll | numeric | | -8 |
action_result.data.\*.data.requests.\*.response.response.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.response.geoip.range | numeric | | 1167286271 |
action_result.data.\*.data.requests.\*.response.response.geoip.region | string | | 16 |
action_result.data.\*.data.requests.\*.response.response.geoip.timezone | string | | Europe/London |
action_result.data.\*.data.requests.\*.response.response.geoip.zip | numeric | | 16245 |
action_result.data.\*.data.requests.\*.response.response.headers.\* | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Accept | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.accept-ch | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Accept-Ranges | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.accept-ranges | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-credentials | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Credentials | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Headers | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-headers | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-method | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Methods | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-methods | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-origin | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Expose-Headers | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-expose-headers | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Max-Age | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-max-age | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Request-Headers | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Request-Method | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Age | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.age | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.allow | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.alt-svc | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Alt-Svc | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.apigw-requestid | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.ats-carp-promotion | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cache-control | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cf-bgj | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cf-cache-status | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cf-polished | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cf-ray | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Connection | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-disposition | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Language | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-language | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Length | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-length | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-md5 | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Security-Policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-security-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-security-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Security-Policy-Report-Only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Type | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-type | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-embedder-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-opener-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-opener-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-resource-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Date | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.date | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.debug | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.display | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.edge-control | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.ETag | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Etag | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.etag | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.expect-ct | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Expect-CT | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.expires | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Expires | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.google-creative-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.google-lineitem-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.google-mediationgroup-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.google-mediationtag-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Keep-Alive | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Last-Modified | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.last-modified | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.link | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Location | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.headers.location | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.headers.nel | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Non-Authoritative-Reason | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.observe-browsing-topics | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Origin | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.headers.p3p | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.P3P | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.permissions-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Permissions-Policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.pragma | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Pragma | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.public-key-pins-report-only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Referer | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.headers.referrer-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Referrer-Policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.report-to | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Server | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.server | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.server-processing-duration-in-ticks | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.server-timing | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.set-cookie | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Set-Cookie | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.status | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Strict-Transport-Security | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.strict-transport-security | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.timing-allow-origin | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Timing-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Transfer-Encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Upgrade | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.User-Agent | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.vary | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Vary | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.version | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Via | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.via | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Amz-Cf-Id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-cf-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Amz-Cf-Pop | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-cf-pop | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-id-2 | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-request-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-server-side-encryption | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-version-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Cache | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-cache | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-cache-status | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-content-type-options | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Content-Type-Options | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-DIS-Request-ID | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-envoy-upstream-service-time | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-fb-content-md5 | string | `md5` | |
action_result.data.\*.data.requests.\*.response.response.headers.x-fb-debug | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-frame-options | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Frame-Options | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Goog-Api-Key | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-generation | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-hash | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-metageneration | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-storage-class | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-stored-content-encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-stored-content-length | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-guploader-uploadid | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-LLID | string | `md5` | |
action_result.data.\*.data.requests.\*.response.response.headers.x-middleton-display | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-mnet-hl2 | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-nbr | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-PINGBACK | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Powered-By | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-rgw-object-type | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Robots-Tag | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-robots-tag | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Same-Domain | string | `domain` | |
action_result.data.\*.data.requests.\*.response.response.headers.x-server | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-sol | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-ua-compatible | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-User-Agent | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-xss-protection | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-XSS-Protection | string | | |
action_result.data.\*.data.requests.\*.response.response.headersText | string | | HTTP/1.1 200 OK |
action_result.data.\*.data.requests.\*.response.response.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.response.response.protocol | string | | h2 |
action_result.data.\*.data.requests.\*.response.response.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.response.rdns.ptr | string | | dns.google |
action_result.data.\*.data.requests.\*.response.response.remoteIPAddress | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.response.remotePort | numeric | | 443 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.\* | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:authority | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:method | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:path | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:scheme | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.accept | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept-Encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.accept-encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept-Language | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.accept-language | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.cache-control | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Connection | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.content-length | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.content-type | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Cookie | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.cookie | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Host | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.origin | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Pragma | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.pragma | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Referer | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.referer | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Dest | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-dest | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-mode | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-site | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-User | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-user | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.upgrade-insecure-requests | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.User-Agent | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.user-agent | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.x-same-domain | string | `domain` | |
action_result.data.\*.data.requests.\*.response.response.requestHeadersText | string | | GET / HTTP/1.1 |
action_result.data.\*.data.requests.\*.response.response.responseTime | numeric | | 1721648282000 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.certificateTransparencyCompliance | string | | compliant |
action_result.data.\*.data.requests.\*.response.response.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.response.response.securityDetails.encryptedClientHello | boolean | | True False |
action_result.data.\*.data.requests.\*.response.response.securityDetails.issuer | string | | WR2 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.keyExchange | string | | ECDHE_RSA |
action_result.data.\*.data.requests.\*.response.response.securityDetails.keyExchangeGroup | string | | X25519 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.protocol | string | | TLS 1.3 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.sanList.\* | string | | ['www.google.com'] |
action_result.data.\*.data.requests.\*.response.response.securityDetails.serverSignatureAlgorithm | numeric | | 1027 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.hashAlgorithm | string | | SHA-256 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.logDescription | string | | Google 'Xenon2024h1' log |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.logId | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.origin | string | | Embedded in certificate |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.signatureAlgorithm | string | | ECDSA |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.signatureData | string | | 3045022100 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.status | string | | Verified |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.timestamp | numeric | | 1719210944000 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.subjectName | string | | www.google.com |
action_result.data.\*.data.requests.\*.response.response.securityDetails.validFrom | numeric | | 1719210944 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.validTo | numeric | | 1726468544 |
action_result.data.\*.data.requests.\*.response.response.securityHeaders.\*.name | string | | x-frame-options |
action_result.data.\*.data.requests.\*.response.response.securityHeaders.\*.value | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.response.response.securityState | string | | secure |
action_result.data.\*.data.requests.\*.response.response.serviceWorkerResponseSource | string | | network |
action_result.data.\*.data.requests.\*.response.response.status | numeric | | 200 |
action_result.data.\*.data.requests.\*.response.response.statusText | string | | OK |
action_result.data.\*.data.requests.\*.response.response.timing.connectEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.connectStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.dnsEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.dnsStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.proxyEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.proxyStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.pushEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.pushStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.receiveHeadersEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.receiveHeadersStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.requestTime | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.sendEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.sendStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.sslEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.sslStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.workerFetchStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.workerReady | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.workerRespondWithSettled | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.workerStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.url | string | `url` | https://www.google.com |
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
action_result.data.\*.meta.processors.abp.state | string | | done |
action_result.data.\*.meta.processors.abp.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.abp.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.abp.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.abp.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.abp.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.abp.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.abp.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.abp.data.\*.country | string | | US |
action_result.data.\*.meta.processors.abp.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.abp.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.abp.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.abp.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.abp.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.abp.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.abp.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.abp.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.abp.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.abp.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.abp.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.abp.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.abp.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.abp.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.abp.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.abp.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.abp.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.abp.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.abp.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.abp.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.asn.state | string | | done |
action_result.data.\*.meta.processors.asn.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.asn.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.asn.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.asn.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.asn.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.asn.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.asn.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.asn.data.\*.country | string | | US |
action_result.data.\*.meta.processors.asn.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.asn.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.asn.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.asn.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.asn.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.asn.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.asn.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.asn.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.asn.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.asn.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.asn.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.asn.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.asn.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.asn.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.asn.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.asn.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.asn.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.asn.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.asn.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.asn.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.cdnjs.state | string | | done |
action_result.data.\*.meta.processors.cdnjs.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.cdnjs.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.cdnjs.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.cdnjs.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.cdnjs.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.cdnjs.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.cdnjs.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.cdnjs.data.\*.country | string | | US |
action_result.data.\*.meta.processors.cdnjs.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.cdnjs.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.cdnjs.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.cdnjs.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.cdnjs.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.cdnjs.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.cdnjs.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.cdnjs.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.cdnjs.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.cdnjs.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.cdnjs.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.cdnjs.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.cdnjs.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.cdnjs.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.cdnjs.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.done.state | string | | done |
action_result.data.\*.meta.processors.done.data.state | string | | done |
action_result.data.\*.meta.processors.geoip.state | string | | done |
action_result.data.\*.meta.processors.geoip.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.geoip.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.geoip.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.geoip.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.geoip.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.geoip.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.geoip.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.geoip.data.\*.country | string | | US |
action_result.data.\*.meta.processors.geoip.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.geoip.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.geoip.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.geoip.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.geoip.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.geoip.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.geoip.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.geoip.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.geoip.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.geoip.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.geoip.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.geoip.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.geoip.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.geoip.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.geoip.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.gsb.state | string | | done |
action_result.data.\*.meta.processors.gsb.data.app | string | | Bootstrap |
action_result.data.\*.meta.processors.gsb.data.asn | string | | AS15169 |
action_result.data.\*.meta.processors.gsb.data.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.gsb.data.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.gsb.data.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.gsb.data.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.gsb.data.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.gsb.data.country | string | | US |
action_result.data.\*.meta.processors.gsb.data.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.gsb.data.description | string | | GOOGLE |
action_result.data.\*.meta.processors.gsb.data.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.gsb.data.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.gsb.data.geoip.country | string | | TR |
action_result.data.\*.meta.processors.gsb.data.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.gsb.data.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.gsb.data.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.gsb.data.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.gsb.data.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.gsb.data.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.gsb.data.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.gsb.data.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.gsb.data.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.gsb.data.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.gsb.data.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.gsb.data.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.gsb.data.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.gsb.data.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.gsb.data.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.gsb.data.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.gsb.data.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.gsb.data.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.gsb.data.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.gsb.data.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.gsb.data.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.gsb.data.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.gsb.data.name | string | | GOOGLE |
action_result.data.\*.meta.processors.gsb.data.ptr | string | | dns.google |
action_result.data.\*.meta.processors.gsb.data.rank | numeric | | 10 |
action_result.data.\*.meta.processors.gsb.data.registrar | string | | arin |
action_result.data.\*.meta.processors.gsb.data.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.gsb.data.source | string | | abp |
action_result.data.\*.meta.processors.gsb.data.type | string | | Document |
action_result.data.\*.meta.processors.gsb.data.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.gsb.data.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.rdns.state | string | | done |
action_result.data.\*.meta.processors.rdns.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.rdns.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.rdns.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.rdns.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.rdns.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.rdns.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.rdns.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.rdns.data.\*.country | string | | US |
action_result.data.\*.meta.processors.rdns.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.rdns.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.rdns.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.rdns.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.rdns.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.rdns.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.rdns.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.rdns.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.rdns.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.rdns.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.rdns.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.rdns.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.rdns.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.rdns.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.rdns.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.umbrella.state | string | | done |
action_result.data.\*.meta.processors.umbrella.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.umbrella.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.umbrella.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.umbrella.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.umbrella.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.umbrella.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.umbrella.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.umbrella.data.\*.country | string | | US |
action_result.data.\*.meta.processors.umbrella.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.umbrella.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.umbrella.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.umbrella.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.umbrella.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.umbrella.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.umbrella.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.umbrella.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.umbrella.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.umbrella.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.umbrella.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.umbrella.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.umbrella.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.umbrella.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.umbrella.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.wappa.state | string | | done |
action_result.data.\*.meta.processors.wappa.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.wappa.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.wappa.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.wappa.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.wappa.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.wappa.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.wappa.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.wappa.data.\*.country | string | | US |
action_result.data.\*.meta.processors.wappa.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.wappa.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.wappa.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.wappa.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.wappa.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.wappa.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.wappa.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.wappa.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.wappa.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.wappa.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.wappa.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.wappa.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.wappa.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.wappa.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.wappa.data.\*.website | string | `url` | https://getbootstrap.com |
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
action_result.data.\*.stats.domainStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.domainStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.domainStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.ipStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.ipStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.ipStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.protocolStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.protocolStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.protocolStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.resourceStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.resourceStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.resourceStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.serverStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.serverStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.serverStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.tlsStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.tlsStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.tlsStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.domainStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.domainStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.domainStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.ipStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.ipStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.ipStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.protocolStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.protocolStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.protocolStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.regDomainStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.regDomainStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.regDomainStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.resourceStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.resourceStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.resourceStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.serverStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.serverStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.serverStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.tlsStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.tlsStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.tlsStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.domainStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.domainStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.domainStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.ipStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.ipStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.ipStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.protocolStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.protocolStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.protocolStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.regDomainStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.regDomainStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.regDomainStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.resourceStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.resourceStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.resourceStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.serverStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.serverStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.serverStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.results.\*.stats.tlsStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.results.\*.stats.tlsStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.results.\*.stats.tlsStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.data.requests.\*.initiatorInfo.columnNumber | numeric | | 88 |
action_result.data.\*.data.requests.\*.initiatorInfo.host | string | | www.google.com |
action_result.data.\*.data.requests.\*.initiatorInfo.lineNumber | numeric | | 27 |
action_result.data.\*.data.requests.\*.initiatorInfo.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.initiatorInfo.stack.callFrames.\*.columnNumber | numeric | | 386 |
action_result.data.\*.data.requests.\*.initiatorInfo.stack.callFrames.\*.functionName | string | | lb |
action_result.data.\*.data.requests.\*.initiatorInfo.stack.callFrames.\*.lineNumber | numeric | | 13 |
action_result.data.\*.data.requests.\*.initiatorInfo.stack.callFrames.\*.scriptId | string | | 40 |
action_result.data.\*.data.requests.\*.initiatorInfo.stack.callFrames.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.initiatorInfo.type | string | | parser |
action_result.data.\*.data.requests.\*.initiatorInfo.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.documentURL | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.frameId | string | | frame |
action_result.data.\*.data.requests.\*.request.hasUserGesture | boolean | | True False |
action_result.data.\*.data.requests.\*.request.initiator.columnNumber | numeric | | 88 |
action_result.data.\*.data.requests.\*.request.initiator.host | string | | www.google.com |
action_result.data.\*.data.requests.\*.request.initiator.lineNumber | numeric | | 27 |
action_result.data.\*.data.requests.\*.request.initiator.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.columnNumber | numeric | | 386 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.functionName | string | | lb |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.lineNumber | numeric | | 13 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.scriptId | string | | 40 |
action_result.data.\*.data.requests.\*.request.initiator.stack.callFrames.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.initiator.type | string | | parser |
action_result.data.\*.data.requests.\*.request.initiator.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.loaderId | string | | loader |
action_result.data.\*.data.requests.\*.request.primaryRequest | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectHasExtraInfo | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.alternateProtocolUsage | string | | unspecifiedReason |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.asn | string | | 43260 |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.country | string | | TR |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.date | string | | 2007-07-04 |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.description | string | | DGN, TR |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.name | string | | DGN |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.registrar | string | | ripencc |
action_result.data.\*.data.requests.\*.request.redirectResponse.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.data.requests.\*.request.redirectResponse.charset | string | | utf-8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.encodedDataLength | numeric | | 1024 |
action_result.data.\*.data.requests.\*.request.redirectResponse.fromDiskCache | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.fromPrefetchCache | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.fromServiceWorker | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.area | numeric | | 100 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.city | string | | Bursa |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.country | string | | TR |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.country_name | string | | Turkey |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.eu | string | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.ll | numeric | | -8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.range | numeric | | 1167286271 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.region | string | | 16 |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.timezone | string | | Europe/London |
action_result.data.\*.data.requests.\*.request.redirectResponse.geoip.zip | numeric | | 16245 |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.\* | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Accept | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.accept-ch | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Accept-Ranges | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.accept-ranges | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-credentials | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Allow-Credentials | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Allow-Headers | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-headers | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-method | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Allow-Methods | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-methods | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-allow-origin | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Expose-Headers | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-expose-headers | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Max-Age | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.access-control-max-age | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Request-Headers | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Access-Control-Request-Method | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Age | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.age | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.allow | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.alt-svc | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Alt-Svc | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.apigw-requestid | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.ats-carp-promotion | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cache-control | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cf-bgj | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cf-cache-status | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cf-polished | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cf-ray | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Connection | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-disposition | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Language | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-language | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Length | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-length | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-md5 | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Security-Policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-security-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-security-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Security-Policy-Report-Only | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Content-Type | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.content-type | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cross-origin-embedder-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cross-origin-opener-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cross-origin-opener-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.cross-origin-resource-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Date | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.date | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.debug | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.display | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.edge-control | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.ETag | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Etag | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.etag | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.expect-ct | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Expect-CT | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.expires | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Expires | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.google-creative-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.google-lineitem-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.google-mediationgroup-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.google-mediationtag-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Keep-Alive | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Last-Modified | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.last-modified | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.link | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Location | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.location | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.nel | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Non-Authoritative-Reason | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.observe-browsing-topics | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Origin | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.p3p | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.P3P | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.permissions-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Permissions-Policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.pragma | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Pragma | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.public-key-pins-report-only | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Referer | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.referrer-policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Referrer-Policy | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.report-to | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Server | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.server | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.server-processing-duration-in-ticks | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.server-timing | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.set-cookie | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Set-Cookie | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.status | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Strict-Transport-Security | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.strict-transport-security | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.timing-allow-origin | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Timing-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Transfer-Encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Upgrade | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.User-Agent | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.vary | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Vary | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.version | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.Via | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.via | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Amz-Cf-Id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-cf-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Amz-Cf-Pop | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-cf-pop | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-id-2 | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-request-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-server-side-encryption | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-amz-version-id | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Cache | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-cache | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-cache-status | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-content-type-options | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Content-Type-Options | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-DIS-Request-ID | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-envoy-upstream-service-time | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-fb-content-md5 | string | `md5` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-fb-debug | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-frame-options | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Frame-Options | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Goog-Api-Key | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-generation | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-hash | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-metageneration | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-storage-class | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-stored-content-encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-goog-stored-content-length | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-guploader-uploadid | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-LLID | string | `md5` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-middleton-display | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-mnet-hl2 | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-nbr | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-PINGBACK | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Powered-By | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-rgw-object-type | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Robots-Tag | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-robots-tag | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-Same-Domain | string | `domain` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-server | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-sol | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-ua-compatible | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-User-Agent | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.x-xss-protection | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headers.X-XSS-Protection | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.headersText | string | | HTTP/1.1 200 OK |
action_result.data.\*.data.requests.\*.request.redirectResponse.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.request.redirectResponse.protocol | string | | h2 |
action_result.data.\*.data.requests.\*.request.redirectResponse.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.rdns.ptr | string | | dns.google |
action_result.data.\*.data.requests.\*.request.redirectResponse.remoteIPAddress | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.request.redirectResponse.remotePort | numeric | | 443 |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.\* | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:authority | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:method | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:path | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.:scheme | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.accept | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept-Encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.accept-encoding | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Accept-Language | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.accept-language | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.cache-control | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Connection | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.content-length | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.content-type | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Cookie | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.cookie | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Host | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.origin | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Pragma | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.pragma | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Referer | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.referer | string | `url` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Dest | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-dest | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-mode | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-site | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Sec-Fetch-User | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.sec-fetch-user | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.upgrade-insecure-requests | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.User-Agent | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.user-agent | string | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeaders.x-same-domain | string | `domain` | |
action_result.data.\*.data.requests.\*.request.redirectResponse.requestHeadersText | string | | GET / HTTP/1.1 |
action_result.data.\*.data.requests.\*.request.redirectResponse.responseTime | numeric | | 1721648282000 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.certificateTransparencyCompliance | string | | compliant |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.encryptedClientHello | boolean | | True False |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.issuer | string | | WR2 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.keyExchange | string | | ECDHE_RSA |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.keyExchangeGroup | string | | X25519 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.protocol | string | | TLS 1.3 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.sanList.\* | string | | ['www.google.com'] |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.serverSignatureAlgorithm | numeric | | 1027 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.hashAlgorithm | string | | SHA-256 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logDescription | string | | Google 'Xenon2024h1' log |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logId | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.origin | string | | Embedded in certificate |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureAlgorithm | string | | ECDSA |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureData | string | | 3045022100 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.status | string | | Verified |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.signedCertificateTimestampList.\*.timestamp | numeric | | 1719210944000 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.subjectName | string | | www.google.com |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.validFrom | numeric | | 1719210944 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityDetails.validTo | numeric | | 1726468544 |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityHeaders.\*.name | string | | x-frame-options |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityHeaders.\*.value | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.request.redirectResponse.securityState | string | | secure |
action_result.data.\*.data.requests.\*.request.redirectResponse.serviceWorkerResponseSource | string | | network |
action_result.data.\*.data.requests.\*.request.redirectResponse.status | numeric | | 200 |
action_result.data.\*.data.requests.\*.request.redirectResponse.statusText | string | | OK |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.connectEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.connectStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.dnsEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.dnsStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.proxyEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.proxyStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.pushEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.pushStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.receiveHeadersEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.receiveHeadersStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.requestTime | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sendEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sendStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sslEnd | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.sslStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerFetchStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerReady | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerRespondWithSettled | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.timing.workerStart | numeric | | |
action_result.data.\*.data.requests.\*.request.redirectResponse.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.request.headers.\* | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Accept | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.accept-ch | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Accept-Ranges | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.accept-ranges | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-allow-credentials | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Allow-Credentials | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Allow-Headers | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-allow-headers | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-allow-method | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Allow-Methods | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-allow-methods | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-allow-origin | string | `url` | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Expose-Headers | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-expose-headers | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Max-Age | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.access-control-max-age | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Request-Headers | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Access-Control-Request-Method | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Age | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.age | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.allow | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.alt-svc | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Alt-Svc | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.apigw-requestid | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.ats-carp-promotion | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cache-control | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cf-bgj | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cf-cache-status | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cf-polished | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cf-ray | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Connection | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-disposition | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Encoding | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-encoding | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Language | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-language | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Length | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-length | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-md5 | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Security-Policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-security-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-security-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Security-Policy-Report-Only | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Content-Type | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.content-type | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cross-origin-embedder-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cross-origin-opener-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cross-origin-opener-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.cross-origin-resource-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Date | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.date | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.debug | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.display | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.edge-control | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.ETag | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Etag | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.etag | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.expect-ct | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Expect-CT | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.expires | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Expires | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.google-creative-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.google-lineitem-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.google-mediationgroup-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.google-mediationtag-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Keep-Alive | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Last-Modified | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.last-modified | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.link | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Location | string | `url` | |
action_result.data.\*.data.requests.\*.request.request.headers.location | string | `url` | |
action_result.data.\*.data.requests.\*.request.request.headers.nel | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Non-Authoritative-Reason | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.observe-browsing-topics | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Origin | string | `url` | |
action_result.data.\*.data.requests.\*.request.request.headers.p3p | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.P3P | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.permissions-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Permissions-Policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.pragma | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Pragma | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.public-key-pins-report-only | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Referer | string | `url` | |
action_result.data.\*.data.requests.\*.request.request.headers.referrer-policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Referrer-Policy | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.report-to | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Server | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.server | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.server-processing-duration-in-ticks | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.server-timing | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.set-cookie | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Set-Cookie | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.status | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Strict-Transport-Security | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.strict-transport-security | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.timing-allow-origin | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Timing-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Transfer-Encoding | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Upgrade | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.User-Agent | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.vary | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Vary | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.version | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.Via | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.via | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Amz-Cf-Id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-cf-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Amz-Cf-Pop | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-cf-pop | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-id-2 | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-request-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-server-side-encryption | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-amz-version-id | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Cache | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-cache | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-cache-status | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-content-type-options | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Content-Type-Options | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-DIS-Request-ID | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-envoy-upstream-service-time | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-fb-content-md5 | string | `md5` | |
action_result.data.\*.data.requests.\*.request.request.headers.x-fb-debug | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-frame-options | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Frame-Options | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Goog-Api-Key | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-generation | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-hash | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-metageneration | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-storage-class | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-stored-content-encoding | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-goog-stored-content-length | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-guploader-uploadid | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-LLID | string | `md5` | |
action_result.data.\*.data.requests.\*.request.request.headers.x-middleton-display | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-mnet-hl2 | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-nbr | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-PINGBACK | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Powered-By | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-rgw-object-type | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Robots-Tag | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-robots-tag | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-Same-Domain | string | `domain` | |
action_result.data.\*.data.requests.\*.request.request.headers.x-server | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-sol | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-ua-compatible | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-User-Agent | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.x-xss-protection | string | | |
action_result.data.\*.data.requests.\*.request.request.headers.X-XSS-Protection | string | | |
action_result.data.\*.data.requests.\*.request.request.hasPostData | boolean | | True False |
action_result.data.\*.data.requests.\*.request.request.initialPriority | string | | VeryHigh |
action_result.data.\*.data.requests.\*.request.request.isLinkPreload | boolean | | True False |
action_result.data.\*.data.requests.\*.request.request.isSameSite | boolean | | True False |
action_result.data.\*.data.requests.\*.request.request.method | string | | GET |
action_result.data.\*.data.requests.\*.request.request.mixedContentType | string | | none |
action_result.data.\*.data.requests.\*.request.request.postData | string | | |
action_result.data.\*.data.requests.\*.request.request.postDataEntries.\*.bytes | string | | payload |
action_result.data.\*.data.requests.\*.request.request.referrerPolicy | string | | strict-origin-when-cross-origin |
action_result.data.\*.data.requests.\*.request.request.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.request.request.urlFragment | string | | fragment |
action_result.data.\*.data.requests.\*.request.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.request.timestamp | numeric | | 1721648282 |
action_result.data.\*.data.requests.\*.request.type | string | | Document |
action_result.data.\*.data.requests.\*.request.wallTime | numeric | | 1721648282 |
action_result.data.\*.data.requests.\*.requests.\*.documentURL | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.frameId | string | | frame |
action_result.data.\*.data.requests.\*.requests.\*.hasUserGesture | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.initiator.columnNumber | numeric | | 88 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.host | string | | www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.initiator.lineNumber | numeric | | 27 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.columnNumber | numeric | | 386 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.functionName | string | | lb |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.lineNumber | numeric | | 13 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.scriptId | string | | 40 |
action_result.data.\*.data.requests.\*.requests.\*.initiator.stack.callFrames.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.initiator.type | string | | parser |
action_result.data.\*.data.requests.\*.requests.\*.initiator.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.loaderId | string | | loader |
action_result.data.\*.data.requests.\*.requests.\*.primaryRequest | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectHasExtraInfo | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.alternateProtocolUsage | string | | unspecifiedReason |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.asn | string | | 43260 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.country | string | | TR |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.date | string | | 2007-07-04 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.description | string | | DGN, TR |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.name | string | | DGN |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.registrar | string | | ripencc |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.charset | string | | utf-8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.encodedDataLength | numeric | | 1024 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.fromDiskCache | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.fromPrefetchCache | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.fromServiceWorker | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.area | numeric | | 100 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.city | string | | Bursa |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.country | string | | TR |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.country_name | string | | Turkey |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.eu | string | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.ll | numeric | | -8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.range | numeric | | 1167286271 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.region | string | | 16 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.timezone | string | | Europe/London |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.geoip.zip | numeric | | 16245 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.\* | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Accept | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.accept-ch | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Accept-Ranges | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.accept-ranges | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-credentials | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Allow-Credentials | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Allow-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-method | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Allow-Methods | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-methods | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-allow-origin | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Expose-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-expose-headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Max-Age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.access-control-max-age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Request-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Access-Control-Request-Method | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.allow | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.alt-svc | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Alt-Svc | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.apigw-requestid | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.ats-carp-promotion | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cache-control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cf-bgj | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cf-cache-status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cf-polished | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cf-ray | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Connection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-disposition | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-md5 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Security-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-security-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-security-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Security-Policy-Report-Only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Content-Type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.content-type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cross-origin-embedder-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cross-origin-opener-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cross-origin-opener-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.cross-origin-resource-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Date | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.date | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.debug | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.display | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.edge-control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.ETag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Etag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.etag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.expect-ct | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Expect-CT | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.expires | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Expires | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.google-creative-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.google-lineitem-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.google-mediationgroup-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.google-mediationtag-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Keep-Alive | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Last-Modified | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.last-modified | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.link | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Location | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.location | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.nel | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Non-Authoritative-Reason | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.observe-browsing-topics | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Origin | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.p3p | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.P3P | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.permissions-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Permissions-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.public-key-pins-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Referer | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.referrer-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Referrer-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.report-to | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.server-processing-duration-in-ticks | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.server-timing | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.set-cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Set-Cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Strict-Transport-Security | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.strict-transport-security | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.timing-allow-origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Timing-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Transfer-Encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Upgrade | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.User-Agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.vary | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Vary | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.version | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.Via | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.via | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Amz-Cf-Id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-cf-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Amz-Cf-Pop | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-cf-pop | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-id-2 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-request-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-server-side-encryption | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-amz-version-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Cache | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-cache | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-cache-status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-content-type-options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Content-Type-Options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-DIS-Request-ID | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-envoy-upstream-service-time | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-fb-content-md5 | string | `md5` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-fb-debug | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-frame-options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Frame-Options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Goog-Api-Key | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-generation | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-hash | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-metageneration | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-storage-class | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-stored-content-encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-goog-stored-content-length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-guploader-uploadid | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-LLID | string | `md5` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-middleton-display | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-mnet-hl2 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-nbr | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-PINGBACK | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Powered-By | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-rgw-object-type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Robots-Tag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-robots-tag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-Same-Domain | string | `domain` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-sol | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-ua-compatible | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-User-Agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.x-xss-protection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headers.X-XSS-Protection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.headersText | string | | HTTP/1.1 200 OK |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.protocol | string | | h2 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.rdns.ptr | string | | dns.google |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.remoteIPAddress | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.remotePort | numeric | | 443 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.\* | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:authority | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:method | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:path | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.:scheme | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept-Encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept-encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Accept-Language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.accept-language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.cache-control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Connection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.content-length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.content-type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Host | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.origin | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Referer | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.referer | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Dest | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-dest | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-mode | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-site | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Sec-Fetch-User | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.sec-fetch-user | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.upgrade-insecure-requests | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.User-Agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.user-agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeaders.x-same-domain | string | `domain` | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.requestHeadersText | string | | GET / HTTP/1.1 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.responseTime | numeric | | 1721648282000 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.certificateTransparencyCompliance | string | | compliant |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.encryptedClientHello | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.issuer | string | | WR2 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.keyExchange | string | | ECDHE_RSA |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.keyExchangeGroup | string | | X25519 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.protocol | string | | TLS 1.3 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.sanList.\* | string | | ['www.google.com'] |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.serverSignatureAlgorithm | numeric | | 1027 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.hashAlgorithm | string | | SHA-256 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logDescription | string | | Google 'Xenon2024h1' log |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.logId | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.origin | string | | Embedded in certificate |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureAlgorithm | string | | ECDSA |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.signatureData | string | | 3045022100 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.status | string | | Verified |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.signedCertificateTimestampList.\*.timestamp | numeric | | 1719210944000 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.subjectName | string | | www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.validFrom | numeric | | 1719210944 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityDetails.validTo | numeric | | 1726468544 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityHeaders.\*.name | string | | x-frame-options |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityHeaders.\*.value | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.securityState | string | | secure |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.serviceWorkerResponseSource | string | | network |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.status | numeric | | 200 |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.statusText | string | | OK |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.connectEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.connectStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.dnsEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.dnsStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.proxyEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.proxyStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.pushEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.pushStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.receiveHeadersEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.receiveHeadersStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.requestTime | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sendEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sendStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sslEnd | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.sslStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerFetchStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerReady | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerRespondWithSettled | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.timing.workerStart | numeric | | |
action_result.data.\*.data.requests.\*.requests.\*.redirectResponse.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.\* | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Accept | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.accept-ch | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Accept-Ranges | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.accept-ranges | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-allow-credentials | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Allow-Credentials | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Allow-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-allow-headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-allow-method | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Allow-Methods | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-allow-methods | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-allow-origin | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Expose-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-expose-headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Max-Age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.access-control-max-age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Request-Headers | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Access-Control-Request-Method | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.age | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.allow | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.alt-svc | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Alt-Svc | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.apigw-requestid | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.ats-carp-promotion | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cache-control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cf-bgj | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cf-cache-status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cf-polished | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cf-ray | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Connection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-disposition | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-language | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-md5 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Security-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-security-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-security-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Security-Policy-Report-Only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Content-Type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.content-type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cross-origin-embedder-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cross-origin-opener-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cross-origin-opener-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.cross-origin-resource-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Date | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.date | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.debug | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.display | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.edge-control | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.ETag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Etag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.etag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.expect-ct | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Expect-CT | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.expires | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Expires | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.google-creative-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.google-lineitem-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.google-mediationgroup-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.google-mediationtag-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Keep-Alive | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Last-Modified | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.last-modified | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.link | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Location | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.location | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.nel | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Non-Authoritative-Reason | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.observe-browsing-topics | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Origin | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.p3p | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.P3P | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.permissions-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Permissions-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Pragma | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.public-key-pins-report-only | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Referer | string | `url` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.referrer-policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Referrer-Policy | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.report-to | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.server-processing-duration-in-ticks | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.server-timing | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.set-cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Set-Cookie | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Strict-Transport-Security | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.strict-transport-security | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.timing-allow-origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Timing-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Transfer-Encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Upgrade | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.User-Agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.vary | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Vary | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.version | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.Via | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.via | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Amz-Cf-Id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-cf-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Amz-Cf-Pop | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-cf-pop | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-id-2 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-request-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-server-side-encryption | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-amz-version-id | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Cache | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-cache | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-cache-status | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-content-type-options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Content-Type-Options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-DIS-Request-ID | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-envoy-upstream-service-time | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-fb-content-md5 | string | `md5` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-fb-debug | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-frame-options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Frame-Options | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Goog-Api-Key | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-generation | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-hash | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-metageneration | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-storage-class | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-stored-content-encoding | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-goog-stored-content-length | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-guploader-uploadid | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-LLID | string | `md5` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-middleton-display | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-mnet-hl2 | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-nbr | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-PINGBACK | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Powered-By | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-rgw-object-type | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Robots-Tag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-robots-tag | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-Same-Domain | string | `domain` | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-server | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-sol | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-ua-compatible | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-User-Agent | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.x-xss-protection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.headers.X-XSS-Protection | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.hasPostData | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.request.initialPriority | string | | VeryHigh |
action_result.data.\*.data.requests.\*.requests.\*.request.isLinkPreload | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.request.isSameSite | boolean | | True False |
action_result.data.\*.data.requests.\*.requests.\*.request.method | string | | GET |
action_result.data.\*.data.requests.\*.requests.\*.request.mixedContentType | string | | none |
action_result.data.\*.data.requests.\*.requests.\*.request.postData | string | | |
action_result.data.\*.data.requests.\*.requests.\*.request.postDataEntries.\*.bytes | string | | payload |
action_result.data.\*.data.requests.\*.requests.\*.request.referrerPolicy | string | | strict-origin-when-cross-origin |
action_result.data.\*.data.requests.\*.requests.\*.request.url | string | `url` | https://www.google.com |
action_result.data.\*.data.requests.\*.requests.\*.request.urlFragment | string | | fragment |
action_result.data.\*.data.requests.\*.requests.\*.requestId | string | | 360549.24 |
action_result.data.\*.data.requests.\*.requests.\*.timestamp | numeric | | 1721648282 |
action_result.data.\*.data.requests.\*.requests.\*.type | string | | Document |
action_result.data.\*.data.requests.\*.requests.\*.wallTime | numeric | | 1721648282 |
action_result.data.\*.data.requests.\*.response.abp.source | string | | abp |
action_result.data.\*.data.requests.\*.response.abp.type | string | | Document |
action_result.data.\*.data.requests.\*.response.abp.url | string | `url` | https://example.com |
action_result.data.\*.data.requests.\*.response.asn.asn | string | | 43260 |
action_result.data.\*.data.requests.\*.response.asn.country | string | | TR |
action_result.data.\*.data.requests.\*.response.asn.date | string | | 2007-07-04 |
action_result.data.\*.data.requests.\*.response.asn.description | string | | DGN, TR |
action_result.data.\*.data.requests.\*.response.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.asn.name | string | | DGN |
action_result.data.\*.data.requests.\*.response.asn.registrar | string | | ripencc |
action_result.data.\*.data.requests.\*.response.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.data.requests.\*.response.dataLength | numeric | | 1024 |
action_result.data.\*.data.requests.\*.response.encodedDataLength | numeric | | 1024 |
action_result.data.\*.data.requests.\*.response.failed.blockedReason | string | | mixed-content |
action_result.data.\*.data.requests.\*.response.failed.canceled | boolean | | True False |
action_result.data.\*.data.requests.\*.response.failed.corsErrorStatus.corsError | string | | MissingAllowOriginHeader |
action_result.data.\*.data.requests.\*.response.failed.corsErrorStatus.failedParameter | string | | |
action_result.data.\*.data.requests.\*.response.failed.errorText | string | | net::ERR_FAILED |
action_result.data.\*.data.requests.\*.response.failed.requestId | string | | 24696.156 |
action_result.data.\*.data.requests.\*.response.failed.timestamp | numeric | | 25061896.916161 |
action_result.data.\*.data.requests.\*.response.failed.type | string | | Document |
action_result.data.\*.data.requests.\*.response.geoip.area | numeric | | 100 |
action_result.data.\*.data.requests.\*.response.geoip.city | string | | Bursa |
action_result.data.\*.data.requests.\*.response.geoip.country | string | | TR |
action_result.data.\*.data.requests.\*.response.geoip.country_name | string | | Turkey |
action_result.data.\*.data.requests.\*.response.geoip.eu | string | | 0 |
action_result.data.\*.data.requests.\*.response.geoip.ll | numeric | | -8 |
action_result.data.\*.data.requests.\*.response.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.geoip.range | numeric | | 1167286271 |
action_result.data.\*.data.requests.\*.response.geoip.region | string | | 16 |
action_result.data.\*.data.requests.\*.response.geoip.timezone | string | | Europe/London |
action_result.data.\*.data.requests.\*.response.geoip.zip | numeric | | 16245 |
action_result.data.\*.data.requests.\*.response.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.file | string | | jquery.js |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.project | string | | jquery |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.source | string | | cdnjs |
action_result.data.\*.data.requests.\*.response.hashmatches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.data.requests.\*.response.hasExtraInfo | boolean | | True False |
action_result.data.\*.data.requests.\*.response.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.rdns.ptr | string | | dns.google |
action_result.data.\*.data.requests.\*.response.requestId | string | | 24696.156 |
action_result.data.\*.data.requests.\*.response.size | numeric | | 1024 |
action_result.data.\*.data.requests.\*.response.type | string | | Document |
action_result.data.\*.data.requests.\*.response.response.alternateProtocolUsage | string | | unspecifiedReason |
action_result.data.\*.data.requests.\*.response.response.asn.asn | string | | 43260 |
action_result.data.\*.data.requests.\*.response.response.asn.country | string | | TR |
action_result.data.\*.data.requests.\*.response.response.asn.date | string | | 2007-07-04 |
action_result.data.\*.data.requests.\*.response.response.asn.description | string | | DGN, TR |
action_result.data.\*.data.requests.\*.response.response.asn.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.response.asn.name | string | | DGN |
action_result.data.\*.data.requests.\*.response.response.asn.registrar | string | | ripencc |
action_result.data.\*.data.requests.\*.response.response.asn.route | string | | 2a00:1288:110::/46 |
action_result.data.\*.data.requests.\*.response.response.charset | string | | utf-8 |
action_result.data.\*.data.requests.\*.response.response.encodedDataLength | numeric | | 1024 |
action_result.data.\*.data.requests.\*.response.response.fromDiskCache | boolean | | True False |
action_result.data.\*.data.requests.\*.response.response.fromPrefetchCache | boolean | | True False |
action_result.data.\*.data.requests.\*.response.response.fromServiceWorker | boolean | | True False |
action_result.data.\*.data.requests.\*.response.response.geoip.area | numeric | | 100 |
action_result.data.\*.data.requests.\*.response.response.geoip.city | string | | Bursa |
action_result.data.\*.data.requests.\*.response.response.geoip.country | string | | TR |
action_result.data.\*.data.requests.\*.response.response.geoip.country_name | string | | Turkey |
action_result.data.\*.data.requests.\*.response.response.geoip.eu | string | | 0 |
action_result.data.\*.data.requests.\*.response.response.geoip.ll | numeric | | -8 |
action_result.data.\*.data.requests.\*.response.response.geoip.metro | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.response.geoip.range | numeric | | 1167286271 |
action_result.data.\*.data.requests.\*.response.response.geoip.region | string | | 16 |
action_result.data.\*.data.requests.\*.response.response.geoip.timezone | string | | Europe/London |
action_result.data.\*.data.requests.\*.response.response.geoip.zip | numeric | | 16245 |
action_result.data.\*.data.requests.\*.response.response.headers.\* | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Accept | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.accept-ch | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Accept-Ranges | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.accept-ranges | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-credentials | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Credentials | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Headers | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-headers | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-method | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Methods | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-methods | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-allow-origin | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Expose-Headers | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-expose-headers | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Max-Age | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.access-control-max-age | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Request-Headers | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Access-Control-Request-Method | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Age | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.age | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.allow | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.alt-svc | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Alt-Svc | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.apigw-requestid | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.ats-carp-promotion | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cache-control | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cf-bgj | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cf-cache-status | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cf-polished | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cf-ray | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Connection | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-disposition | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Language | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-language | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Length | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-length | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-md5 | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Security-Policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-security-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-security-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Security-Policy-Report-Only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Content-Type | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.content-type | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-embedder-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-opener-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-opener-policy-report-only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.cross-origin-resource-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Date | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.date | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.debug | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.display | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.edge-control | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.ETag | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Etag | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.etag | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.expect-ct | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Expect-CT | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.expires | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Expires | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.google-creative-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.google-lineitem-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.google-mediationgroup-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.google-mediationtag-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Keep-Alive | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Last-Modified | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.last-modified | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.link | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Location | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.headers.location | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.headers.nel | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Non-Authoritative-Reason | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.observe-browsing-topics | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Origin | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.headers.p3p | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.P3P | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.permissions-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Permissions-Policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.pragma | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Pragma | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Public-Key-Pins-Report-Only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.public-key-pins-report-only | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Referer | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.headers.referrer-policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Referrer-Policy | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.report-to | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Server | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.server | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.server-processing-duration-in-ticks | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.server-timing | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.set-cookie | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Set-Cookie | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.status | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Strict-Transport-Security | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.strict-transport-security | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.timing-allow-origin | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Timing-Allow-Origin | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Transfer-Encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Upgrade | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.User-Agent | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.vary | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Vary | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.version | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.Via | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.via | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Amz-Cf-Id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-cf-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Amz-Cf-Pop | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-cf-pop | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-id-2 | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-request-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-server-side-encryption | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-amz-version-id | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Cache | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-cache | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-cache-status | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-content-type-options | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Content-Type-Options | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-DIS-Request-ID | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-envoy-upstream-service-time | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-fb-content-md5 | string | `md5` | |
action_result.data.\*.data.requests.\*.response.response.headers.x-fb-debug | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-frame-options | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Frame-Options | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Goog-Api-Key | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-generation | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-hash | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-metageneration | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-storage-class | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-stored-content-encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-goog-stored-content-length | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-guploader-uploadid | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-LLID | string | `md5` | |
action_result.data.\*.data.requests.\*.response.response.headers.x-middleton-display | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-mnet-hl2 | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-nbr | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-PINGBACK | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Powered-By | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-rgw-object-type | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Robots-Tag | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-robots-tag | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-Same-Domain | string | `domain` | |
action_result.data.\*.data.requests.\*.response.response.headers.x-server | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-sol | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-ua-compatible | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-User-Agent | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.x-xss-protection | string | | |
action_result.data.\*.data.requests.\*.response.response.headers.X-XSS-Protection | string | | |
action_result.data.\*.data.requests.\*.response.response.headersText | string | | HTTP/1.1 200 OK |
action_result.data.\*.data.requests.\*.response.response.mimeType | string | | text/html |
action_result.data.\*.data.requests.\*.response.response.protocol | string | | h2 |
action_result.data.\*.data.requests.\*.response.response.rdns.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.response.rdns.ptr | string | | dns.google |
action_result.data.\*.data.requests.\*.response.response.remoteIPAddress | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.data.requests.\*.response.response.remotePort | numeric | | 443 |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.\* | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:authority | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:method | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:path | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.:scheme | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.accept | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept-Encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.accept-encoding | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Accept-Language | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.accept-language | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Cache-Control | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.cache-control | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Connection | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.content-length | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.content-type | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Cookie | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.cookie | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Host | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.origin | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Pragma | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.pragma | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Referer | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.referer | string | `url` | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Dest | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-dest | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Mode | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-mode | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-Site | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-site | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Sec-Fetch-User | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.sec-fetch-user | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.Upgrade-Insecure-Requests | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.upgrade-insecure-requests | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.User-Agent | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.user-agent | string | | |
action_result.data.\*.data.requests.\*.response.response.requestHeaders.x-same-domain | string | `domain` | |
action_result.data.\*.data.requests.\*.response.response.requestHeadersText | string | | GET / HTTP/1.1 |
action_result.data.\*.data.requests.\*.response.response.responseTime | numeric | | 1721648282000 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.certificateId | numeric | | 0 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.certificateTransparencyCompliance | string | | compliant |
action_result.data.\*.data.requests.\*.response.response.securityDetails.cipher | string | | AES_128_GCM |
action_result.data.\*.data.requests.\*.response.response.securityDetails.encryptedClientHello | boolean | | True False |
action_result.data.\*.data.requests.\*.response.response.securityDetails.issuer | string | | WR2 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.keyExchange | string | | ECDHE_RSA |
action_result.data.\*.data.requests.\*.response.response.securityDetails.keyExchangeGroup | string | | X25519 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.protocol | string | | TLS 1.3 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.sanList.\* | string | | ['www.google.com'] |
action_result.data.\*.data.requests.\*.response.response.securityDetails.serverSignatureAlgorithm | numeric | | 1027 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.hashAlgorithm | string | | SHA-256 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.logDescription | string | | Google 'Xenon2024h1' log |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.logId | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.origin | string | | Embedded in certificate |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.signatureAlgorithm | string | | ECDSA |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.signatureData | string | | 3045022100 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.status | string | | Verified |
action_result.data.\*.data.requests.\*.response.response.securityDetails.signedCertificateTimestampList.\*.timestamp | numeric | | 1719210944000 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.subjectName | string | | www.google.com |
action_result.data.\*.data.requests.\*.response.response.securityDetails.validFrom | numeric | | 1719210944 |
action_result.data.\*.data.requests.\*.response.response.securityDetails.validTo | numeric | | 1726468544 |
action_result.data.\*.data.requests.\*.response.response.securityHeaders.\*.name | string | | x-frame-options |
action_result.data.\*.data.requests.\*.response.response.securityHeaders.\*.value | string | | SAMEORIGIN |
action_result.data.\*.data.requests.\*.response.response.securityState | string | | secure |
action_result.data.\*.data.requests.\*.response.response.serviceWorkerResponseSource | string | | network |
action_result.data.\*.data.requests.\*.response.response.status | numeric | | 200 |
action_result.data.\*.data.requests.\*.response.response.statusText | string | | OK |
action_result.data.\*.data.requests.\*.response.response.timing.connectEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.connectStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.dnsEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.dnsStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.proxyEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.proxyStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.pushEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.pushStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.receiveHeadersEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.receiveHeadersStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.requestTime | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.sendEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.sendStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.sslEnd | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.sslStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.workerFetchStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.workerReady | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.workerRespondWithSettled | numeric | | |
action_result.data.\*.data.requests.\*.response.response.timing.workerStart | numeric | | |
action_result.data.\*.data.requests.\*.response.response.url | string | `url` | https://www.google.com |
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
action_result.data.\*.meta.processors.abp.state | string | | done |
action_result.data.\*.meta.processors.abp.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.abp.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.abp.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.abp.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.abp.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.abp.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.abp.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.abp.data.\*.country | string | | US |
action_result.data.\*.meta.processors.abp.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.abp.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.abp.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.abp.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.abp.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.abp.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.abp.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.abp.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.abp.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.abp.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.abp.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.abp.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.abp.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.abp.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.abp.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.abp.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.abp.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.abp.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.abp.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.abp.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.abp.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.abp.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.asn.state | string | | done |
action_result.data.\*.meta.processors.asn.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.asn.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.asn.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.asn.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.asn.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.asn.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.asn.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.asn.data.\*.country | string | | US |
action_result.data.\*.meta.processors.asn.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.asn.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.asn.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.asn.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.asn.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.asn.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.asn.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.asn.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.asn.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.asn.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.asn.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.asn.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.asn.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.asn.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.asn.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.asn.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.asn.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.asn.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.asn.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.asn.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.asn.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.asn.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.cdnjs.state | string | | done |
action_result.data.\*.meta.processors.cdnjs.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.cdnjs.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.cdnjs.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.cdnjs.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.cdnjs.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.cdnjs.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.cdnjs.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.cdnjs.data.\*.country | string | | US |
action_result.data.\*.meta.processors.cdnjs.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.cdnjs.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.cdnjs.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.cdnjs.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.cdnjs.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.cdnjs.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.cdnjs.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.cdnjs.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.cdnjs.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.cdnjs.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.cdnjs.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.cdnjs.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.cdnjs.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.cdnjs.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.cdnjs.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.cdnjs.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.cdnjs.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.done.state | string | | done |
action_result.data.\*.meta.processors.done.data.state | string | | done |
action_result.data.\*.meta.processors.geoip.state | string | | done |
action_result.data.\*.meta.processors.geoip.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.geoip.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.geoip.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.geoip.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.geoip.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.geoip.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.geoip.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.geoip.data.\*.country | string | | US |
action_result.data.\*.meta.processors.geoip.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.geoip.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.geoip.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.geoip.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.geoip.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.geoip.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.geoip.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.geoip.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.geoip.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.geoip.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.geoip.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.geoip.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.geoip.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.geoip.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.geoip.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.geoip.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.geoip.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.gsb.state | string | | done |
action_result.data.\*.meta.processors.gsb.data.app | string | | Bootstrap |
action_result.data.\*.meta.processors.gsb.data.asn | string | | AS15169 |
action_result.data.\*.meta.processors.gsb.data.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.gsb.data.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.gsb.data.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.gsb.data.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.gsb.data.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.gsb.data.country | string | | US |
action_result.data.\*.meta.processors.gsb.data.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.gsb.data.description | string | | GOOGLE |
action_result.data.\*.meta.processors.gsb.data.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.gsb.data.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.gsb.data.geoip.country | string | | TR |
action_result.data.\*.meta.processors.gsb.data.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.gsb.data.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.gsb.data.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.gsb.data.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.gsb.data.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.gsb.data.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.gsb.data.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.gsb.data.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.gsb.data.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.gsb.data.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.gsb.data.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.gsb.data.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.gsb.data.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.gsb.data.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.gsb.data.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.gsb.data.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.gsb.data.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.gsb.data.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.gsb.data.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.gsb.data.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.gsb.data.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.gsb.data.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.gsb.data.name | string | | GOOGLE |
action_result.data.\*.meta.processors.gsb.data.ptr | string | | dns.google |
action_result.data.\*.meta.processors.gsb.data.rank | numeric | | 10 |
action_result.data.\*.meta.processors.gsb.data.registrar | string | | arin |
action_result.data.\*.meta.processors.gsb.data.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.gsb.data.source | string | | abp |
action_result.data.\*.meta.processors.gsb.data.type | string | | Document |
action_result.data.\*.meta.processors.gsb.data.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.gsb.data.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.rdns.state | string | | done |
action_result.data.\*.meta.processors.rdns.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.rdns.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.rdns.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.rdns.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.rdns.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.rdns.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.rdns.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.rdns.data.\*.country | string | | US |
action_result.data.\*.meta.processors.rdns.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.rdns.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.rdns.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.rdns.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.rdns.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.rdns.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.rdns.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.rdns.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.rdns.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.rdns.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.rdns.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.rdns.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.rdns.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.rdns.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.rdns.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.rdns.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.rdns.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.umbrella.state | string | | done |
action_result.data.\*.meta.processors.umbrella.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.umbrella.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.umbrella.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.umbrella.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.umbrella.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.umbrella.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.umbrella.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.umbrella.data.\*.country | string | | US |
action_result.data.\*.meta.processors.umbrella.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.umbrella.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.umbrella.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.umbrella.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.umbrella.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.umbrella.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.umbrella.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.umbrella.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.umbrella.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.umbrella.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.umbrella.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.umbrella.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.umbrella.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.umbrella.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.umbrella.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.umbrella.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.umbrella.data.\*.website | string | `url` | https://getbootstrap.com |
action_result.data.\*.meta.processors.wappa.state | string | | done |
action_result.data.\*.meta.processors.wappa.data.\*.app | string | | Bootstrap |
action_result.data.\*.meta.processors.wappa.data.\*.asn | string | | AS15169 |
action_result.data.\*.meta.processors.wappa.data.\*.categories.\*.name | string | | Web Frameworks |
action_result.data.\*.meta.processors.wappa.data.\*.categories.\*.priority | numeric | | 7 |
action_result.data.\*.meta.processors.wappa.data.\*.confidence.\*.confidence | numeric | | 100 |
action_result.data.\*.meta.processors.wappa.data.\*.confidence.\*.pattern | string | | bootstrap |
action_result.data.\*.meta.processors.wappa.data.\*.confidenceTotal | numeric | | 100 |
action_result.data.\*.meta.processors.wappa.data.\*.country | string | | US |
action_result.data.\*.meta.processors.wappa.data.\*.date | string | | 2024-01-01 |
action_result.data.\*.meta.processors.wappa.data.\*.description | string | | GOOGLE |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.area | numeric | | 100 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.city | string | | Bursa |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.country | string | | TR |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.country_name | string | | Turkey |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.eu | string | | 0 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.ll | numeric | | -8 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.metro | numeric | | 0 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.range | numeric | | 1167286271 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.region | string | | 16 |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.timezone | string | | Europe/London |
action_result.data.\*.meta.processors.wappa.data.\*.geoip.zip | numeric | | 16245 |
action_result.data.\*.meta.processors.wappa.data.\*.hash | string | `sha256` | 0000000000000000000000000000000000000000000000000000000000000000 |
action_result.data.\*.meta.processors.wappa.data.\*.hostname | string | `domain` | www.google.com |
action_result.data.\*.meta.processors.wappa.data.\*.icon | string | | Bootstrap.png |
action_result.data.\*.meta.processors.wappa.data.\*.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.cacheDuration | string | | 300s |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.file | string | | jquery.js |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.platformType | string | | ANY_PLATFORM |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.project | string | | jquery |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.project_url | string | `url` | https://example.com/project |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.source | string | | cdnjs |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.threat.url | string | `url` | https://example.com |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.threatEntryType | string | | URL |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.threatType | string | | MALWARE |
action_result.data.\*.meta.processors.wappa.data.\*.matches.\*.url | string | `url` | https://example.com/file.js |
action_result.data.\*.meta.processors.wappa.data.\*.name | string | | GOOGLE |
action_result.data.\*.meta.processors.wappa.data.\*.ptr | string | | dns.google |
action_result.data.\*.meta.processors.wappa.data.\*.rank | numeric | | 10 |
action_result.data.\*.meta.processors.wappa.data.\*.registrar | string | | arin |
action_result.data.\*.meta.processors.wappa.data.\*.route | string | | 8.8.8.0/24 |
action_result.data.\*.meta.processors.wappa.data.\*.source | string | | abp |
action_result.data.\*.meta.processors.wappa.data.\*.type | string | | Document |
action_result.data.\*.meta.processors.wappa.data.\*.url | string | `url` | https://www.google.com |
action_result.data.\*.meta.processors.wappa.data.\*.website | string | `url` | https://getbootstrap.com |
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
action_result.data.\*.stats.domainStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.domainStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.domainStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.ipStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.ipStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.ipStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.protocolStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.protocolStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.protocolStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.regDomainStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.resourceStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.resourceStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.resourceStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.serverStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.serverStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.serverStats.\*.subDomains.\*.failed | boolean | | True False |
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
action_result.data.\*.stats.tlsStats.\*.subDomains.\*.country | string | | IE |
action_result.data.\*.stats.tlsStats.\*.subDomains.\*.domain | string | `domain` | example.com |
action_result.data.\*.stats.tlsStats.\*.subDomains.\*.failed | boolean | | True False |
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
