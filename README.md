[comment]: # "Auto-generated SOAR connector documentation"
# urlscan\.io

Publisher: Splunk  
Connector Version: 2\.1\.12  
Product Vendor: urlscan\.io  
Product Name: urlscan\.io  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app supports investigative actions on urlscan\.io

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2017-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
The **api_key** field is not required to use this app, as **urlscan.io** does not require an API key
for querying its database. However, if you wish to start a scan with **detonate url** , then you
will need an API key configured.  


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a urlscan\.io asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_key** |  optional  | password | API key for urlscan\.io
**timeout** |  optional  | numeric | Timeout period for action \(seconds\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get report](#action-get-report) - Query for results of an already completed detonation  
[lookup domain](#action-lookup-domain) - Find information about a domain at urlscan\.io  
[lookup ip](#action-lookup-ip) - Find information about an IP address at urlscan\.io  
[detonate url](#action-detonate-url) - Detonate a URL at urlscan\.io  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

This will attempt to connect by running an action which would require usage of the API key\. If there is no API key set, it will still run a query to make sure the <b>urlscan\.io</b> API can be queried\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get report'
Query for results of an already completed detonation

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Detonation ID for the desired report | string |  `urlscan submission id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `urlscan submission id` 
action\_result\.data\.\*\.data\.console\.\*\.message\.column | numeric | 
action\_result\.data\.\*\.data\.console\.\*\.message\.level | string | 
action\_result\.data\.\*\.data\.console\.\*\.message\.line | numeric | 
action\_result\.data\.\*\.data\.console\.\*\.message\.source | string | 
action\_result\.data\.\*\.data\.console\.\*\.message\.text | string | 
action\_result\.data\.\*\.data\.console\.\*\.message\.url | string |  `url` 
action\_result\.data\.\*\.data\.cookies\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.data\.cookies\.\*\.expires | numeric | 
action\_result\.data\.\*\.data\.cookies\.\*\.httpOnly | boolean | 
action\_result\.data\.\*\.data\.cookies\.\*\.name | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.path | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.priority | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.sameParty | boolean | 
action\_result\.data\.\*\.data\.cookies\.\*\.sameSite | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.secure | boolean | 
action\_result\.data\.\*\.data\.cookies\.\*\.session | boolean | 
action\_result\.data\.\*\.data\.cookies\.\*\.size | numeric | 
action\_result\.data\.\*\.data\.cookies\.\*\.sourcePort | numeric | 
action\_result\.data\.\*\.data\.cookies\.\*\.sourceScheme | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.value | string | 
action\_result\.data\.\*\.data\.globals\.\*\.prop | string | 
action\_result\.data\.\*\.data\.globals\.\*\.type | string | 
action\_result\.data\.\*\.data\.links\.\*\.href | string |  `url` 
action\_result\.data\.\*\.data\.links\.\*\.text | string | 
action\_result\.data\.\*\.data\.requests\.\*\.initiatorInfo\.host | string | 
action\_result\.data\.\*\.data\.requests\.\*\.initiatorInfo\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.initiatorInfo\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.documentURL | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.frameId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.hasUserGesture | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.columnNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.lineNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.stack\.callFrames\.\*\.columnNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.stack\.callFrames\.\*\.functionName | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.stack\.callFrames\.\*\.lineNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.stack\.callFrames\.\*\.scriptId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.stack\.callFrames\.\*\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.loaderId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.primaryRequest | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.encodedDataLength | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.fromPrefetchCache | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.\* | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Content\-Length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Location | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Strict\-Transport\-Security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.mimeType | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.protocol | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.remoteIPAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.remotePort | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Accept | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Accept\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Accept\-Language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Cache\-Control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Host | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Dest | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Mode | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Site | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Sec\-Fetch\-User | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.User\-Agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.responseTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.certificateId | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.certificateTransparencyCompliance | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.cipher | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.issuer | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.keyExchange | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.keyExchangeGroup | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.protocol | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.sanList | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.subjectName | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.validFrom | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.validTo | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityState | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.status | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.statusText | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.connectEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.connectStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.dnsEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.dnsStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.proxyEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.proxyStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.pushEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.pushStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.receiveHeadersEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.requestTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.sendEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.sendStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.sslEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.sslStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.workerFetchStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.workerReady | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.workerRespondWithSettled | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.workerStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.hasPostData | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.\* | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.Content\-Type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.Origin | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.Referer | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.User\-Agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.initialPriority | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.method | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.mixedContentType | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.postData | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.postDataEntries\.\*\.bytes | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.referrerPolicy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.requestId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.timestamp | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.wallTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.documentURL | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.frameId | string |  `md5` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.hasUserGesture | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.initiator\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.loaderId | string |  `md5` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.asn | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.country | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.description | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.name | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.registrar | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.route | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.encodedDataLength | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.fromPrefetchCache | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.area | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.city | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.country | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.country\_name | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.eu | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.ll | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.metro | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.range | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.region | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.timezone | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Cache\-Control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Content\-Language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Content\-Length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Content\-Security\-Policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Content\-Type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Location | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Set\-Cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Strict\-Transport\-Security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.X\-Frame\-Options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.X\-XSS\-Protection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.cache\-control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.content\-language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.content\-length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.content\-security\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.content\-type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.expect\-ct | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.location | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.referrer\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.set\-cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.strict\-transport\-security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.x\-content\-type\-options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.x\-frame\-options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.x\-xss\-protection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.mimeType | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.protocol | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.rdns\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.rdns\.ptr | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.remoteIPAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.remotePort | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.\:authority | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.\:method | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.\:path | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.\:scheme | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Accept | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Accept\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Accept\-Language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Cache\-Control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Host | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Dest | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Mode | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Site | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Sec\-Fetch\-User | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.User\-Agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.accept | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.accept\-encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.accept\-language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.cache\-control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.sec\-fetch\-dest | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.sec\-fetch\-mode | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.sec\-fetch\-site | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.sec\-fetch\-user | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.upgrade\-insecure\-requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.user\-agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.responseTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.certificateId | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.certificateTransparencyCompliance | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.cipher | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.issuer | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.keyExchange | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.keyExchangeGroup | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.protocol | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.sanList | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.subjectName | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.validFrom | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.validTo | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityState | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.status | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.statusText | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.connectEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.connectStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.dnsEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.dnsStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.proxyEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.proxyStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.pushEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.pushStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.receiveHeadersEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.requestTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.sendEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.sendStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.sslEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.sslStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.workerFetchStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.workerReady | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.workerRespondWithSettled | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.workerStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.headers\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.headers\.User\-Agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.initialPriority | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.method | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.mixedContentType | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.referrerPolicy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.requestId | string |  `md5` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.wallTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.abp\.source | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.abp\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.abp\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.asn | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.country | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.description | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.name | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.registrar | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.route | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.dataLength | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.encodedDataLength | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.blockedReason | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.canceled | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.errorText | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.requestId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.timestamp | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.area | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.city | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.country | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.country\_name | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.eu | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.ll | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.metro | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.range | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.region | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.timezone | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.zip | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hash | string |  `sha256` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hashmatches\.\*\.file | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hashmatches\.\*\.project | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hashmatches\.\*\.project\_url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hashmatches\.\*\.source | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hashmatches\.\*\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.rdns\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.rdns\.ptr | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.requestId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.encodedDataLength | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.fromPrefetchCache | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.\* | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Accept\-Ranges | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Allow\-Credentials | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Allow\-Headers | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Allow\-Methods | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Allow\-Origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Expose\-Headers | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Max\-Age | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Age | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Alt\-Svc | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Cache\-Control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Content\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Content\-Length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Content\-Security\-Policy\-Report\-Only | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Content\-Type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.ETag | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Etag | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Expect\-CT | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Expires | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Keep\-Alive | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Last\-Modified | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Public\-Key\-Pins\-Report\-Only | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Referrer\-Policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Strict\-Transport\-Security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Timing\-Allow\-Origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Upgrade | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Via | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Amz\-Cf\-Id | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Amz\-Cf\-Pop | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Cache | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Content\-Type\-Options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Frame\-Options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-LLID | string |  `md5` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Powered\-By | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-XSS\-Protection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.accept\-ranges | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.access\-control\-allow\-methods | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.access\-control\-allow\-origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.age | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.alt\-svc | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.ats\-carp\-promotion | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.cache\-control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-security\-policy\-report\-only | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.etag | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.expect\-ct | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.expires | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.last\-modified | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.link | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.referrer\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.status | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.strict\-transport\-security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.timing\-allow\-origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.vary | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.via | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-amz\-cf\-id | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-amz\-cf\-pop | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-amz\-id\-2 | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-amz\-request\-id | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-amz\-server\-side\-encryption | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-cache | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-content\-type\-options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-frame\-options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-xss\-protection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.mimeType | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.protocol | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.remoteIPAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.remotePort | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.\* | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Accept | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Accept\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Accept\-Language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Cache\-Control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Host | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Sec\-Fetch\-Dest | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Sec\-Fetch\-Mode | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Sec\-Fetch\-Site | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Sec\-Fetch\-User | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.User\-Agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.responseTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.certificateId | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.certificateTransparencyCompliance | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.cipher | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.issuer | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.keyExchange | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.keyExchangeGroup | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.protocol | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.sanList | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.hashAlgorithm | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.logDescription | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.logId | string |  `sha256` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.signatureAlgorithm | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.signatureData | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.status | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.subjectName | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.validFrom | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.validTo | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityHeaders\.\*\.name | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityHeaders\.\*\.value | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityState | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.status | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.statusText | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.connectEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.connectStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.dnsEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.dnsStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.proxyEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.proxyStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.pushEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.pushStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.receiveHeadersEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.requestTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.sendEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.sendStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.sslEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.sslStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.workerFetchStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.workerReady | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.workerRespondWithSettled | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.workerStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.size | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.type | string | 
action\_result\.data\.\*\.data\.timing\.beginNavigation | string | 
action\_result\.data\.\*\.data\.timing\.domContentEventFired | string | 
action\_result\.data\.\*\.data\.timing\.frameNavigated | string | 
action\_result\.data\.\*\.data\.timing\.frameStartedLoading | string | 
action\_result\.data\.\*\.data\.timing\.frameStoppedLoading | string | 
action\_result\.data\.\*\.data\.timing\.loadEventFired | string | 
action\_result\.data\.\*\.lists\.asns | string | 
action\_result\.data\.\*\.lists\.certificates\.\*\.issuer | string | 
action\_result\.data\.\*\.lists\.certificates\.\*\.sanList | string | 
action\_result\.data\.\*\.lists\.certificates\.\*\.subjectName | string | 
action\_result\.data\.\*\.lists\.certificates\.\*\.validFrom | numeric | 
action\_result\.data\.\*\.lists\.certificates\.\*\.validTo | numeric | 
action\_result\.data\.\*\.lists\.countries | string | 
action\_result\.data\.\*\.lists\.domains | string | 
action\_result\.data\.\*\.lists\.hashes | string |  `sha256` 
action\_result\.data\.\*\.lists\.ips | string | 
action\_result\.data\.\*\.lists\.linkDomains | string | 
action\_result\.data\.\*\.lists\.servers | string | 
action\_result\.data\.\*\.lists\.urls | string |  `url` 
action\_result\.data\.\*\.meta\.processors\.abp\.data\.\*\.source | string | 
action\_result\.data\.\*\.meta\.processors\.abp\.data\.\*\.type | string | 
action\_result\.data\.\*\.meta\.processors\.abp\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.meta\.processors\.abp\.state | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.asn | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.country | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.date | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.description | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.name | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.registrar | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.route | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.state | string | 
action\_result\.data\.\*\.meta\.processors\.cdnjs\.data\.\*\.hash | string |  `sha256` 
action\_result\.data\.\*\.meta\.processors\.cdnjs\.data\.\*\.matches | string | 
action\_result\.data\.\*\.meta\.processors\.cdnjs\.state | string | 
action\_result\.data\.\*\.meta\.processors\.done\.data\.state | string | 
action\_result\.data\.\*\.meta\.processors\.done\.state | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.area | numeric | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.city | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.country | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.country\_name | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.eu | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.ll | numeric | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.metro | numeric | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.range | numeric | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.region | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.timezone | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.zip | numeric | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.meta\.processors\.geoip\.state | string | 
action\_result\.data\.\*\.meta\.processors\.gsb\.data\.matches\.\*\.cacheDuration | string | 
action\_result\.data\.\*\.meta\.processors\.gsb\.data\.matches\.\*\.platformType | string | 
action\_result\.data\.\*\.meta\.processors\.gsb\.data\.matches\.\*\.threat\.url | string |  `url` 
action\_result\.data\.\*\.meta\.processors\.gsb\.data\.matches\.\*\.threatEntryType | string | 
action\_result\.data\.\*\.meta\.processors\.gsb\.data\.matches\.\*\.threatType | string | 
action\_result\.data\.\*\.meta\.processors\.gsb\.state | string | 
action\_result\.data\.\*\.meta\.processors\.rdns\.data\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.meta\.processors\.rdns\.data\.\*\.ptr | string | 
action\_result\.data\.\*\.meta\.processors\.rdns\.state | string | 
action\_result\.data\.\*\.meta\.processors\.wappa\.state | string | 
action\_result\.data\.\*\.page\.asn | string | 
action\_result\.data\.\*\.page\.asnname | string | 
action\_result\.data\.\*\.page\.city | string | 
action\_result\.data\.\*\.page\.country | string | 
action\_result\.data\.\*\.page\.domain | string |  `domain` 
action\_result\.data\.\*\.page\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.page\.ptr | string | 
action\_result\.data\.\*\.page\.server | string | 
action\_result\.data\.\*\.page\.url | string |  `url` 
action\_result\.data\.\*\.stats\.IPv6Percentage | numeric | 
action\_result\.data\.\*\.stats\.adBlocked | numeric | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.stats\.domainStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.index | numeric | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.initiators | string | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.ips | string | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.redirects | numeric | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.asn | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.country | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.date | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.description | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.ip | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.name | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.registrar | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.route | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.count | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.domains | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.area | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.city | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.country | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.country\_name | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.eu | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.ll | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.metro | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.range | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.region | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.timezone | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.zip | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.index | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.stats\.ipStats\.\*\.ipv6 | boolean | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.rdns\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.stats\.ipStats\.\*\.rdns\.ptr | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.redirects | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.requests | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.malicious | numeric | 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.ips | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.protocol | string |  `url` 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.index | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.ips | string | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.redirects | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.regDomain | string |  `domain` 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.subDomains\.\*\.country | string | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.subDomains\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.subDomains\.\*\.failed | boolean | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.compression | string | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.ips | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.latency | numeric | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.percentage | numeric | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.type | string | 
action\_result\.data\.\*\.stats\.securePercentage | numeric | 
action\_result\.data\.\*\.stats\.secureRequests | numeric | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.ips | string | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.server | string | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.ips | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.protocols\.TLS 1\.2 / ECDHE\_ECDSA / AES\_128\_GCM | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.protocols\.TLS 1\.2 / ECDHE\_RSA / AES\_128\_GCM | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.protocols\.TLS 1\.3 /  / AES\_128\_GCM | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.protocols\.TLS 1\.3 /  / AES\_256\_GCM | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.securityState | string | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.totalLinks | numeric | 
action\_result\.data\.\*\.stats\.uniqCountries | numeric | 
action\_result\.data\.\*\.submitter\.country | string | 
action\_result\.data\.\*\.task\.domURL | string |  `url` 
action\_result\.data\.\*\.task\.method | string | 
action\_result\.data\.\*\.task\.options\.useragent | string | 
action\_result\.data\.\*\.task\.reportURL | string |  `url` 
action\_result\.data\.\*\.task\.screenshotURL | string |  `url` 
action\_result\.data\.\*\.task\.source | string | 
action\_result\.data\.\*\.task\.time | string | 
action\_result\.data\.\*\.task\.url | string |  `url` 
action\_result\.data\.\*\.task\.userAgent | string | 
action\_result\.data\.\*\.task\.uuid | string |  `urlscan submission id` 
action\_result\.data\.\*\.task\.visibility | string | 
action\_result\.data\.\*\.verdicts\.community\.score | numeric | 
action\_result\.data\.\*\.verdicts\.community\.votesBenign | numeric | 
action\_result\.data\.\*\.verdicts\.community\.votesMalicious | numeric | 
action\_result\.data\.\*\.verdicts\.community\.votesTotal | numeric | 
action\_result\.data\.\*\.verdicts\.engines\.benignTotal | numeric | 
action\_result\.data\.\*\.verdicts\.engines\.enginesTotal | numeric | 
action\_result\.data\.\*\.verdicts\.engines\.maliciousTotal | numeric | 
action\_result\.data\.\*\.verdicts\.engines\.score | numeric | 
action\_result\.data\.\*\.verdicts\.overall\.hasVerdicts | numeric | 
action\_result\.data\.\*\.verdicts\.overall\.malicious | boolean | 
action\_result\.data\.\*\.verdicts\.overall\.score | numeric | 
action\_result\.data\.\*\.verdicts\.urlscan\.malicious | boolean | 
action\_result\.data\.\*\.verdicts\.urlscan\.score | numeric | 
action\_result\.summary\.report\_uuid | string |  `urlscan submission id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup domain'
Find information about a domain at urlscan\.io

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to lookup | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.has\_more | boolean | 
action\_result\.data\.\*\.results\.\*\.\_id | string | 
action\_result\.data\.\*\.results\.\*\.indexedAt | string | 
action\_result\.data\.\*\.results\.\*\.page\.asn | string | 
action\_result\.data\.\*\.results\.\*\.page\.asnname | string | 
action\_result\.data\.\*\.results\.\*\.page\.city | string | 
action\_result\.data\.\*\.results\.\*\.page\.country | string | 
action\_result\.data\.\*\.results\.\*\.page\.domain | string |  `domain` 
action\_result\.data\.\*\.results\.\*\.page\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.results\.\*\.page\.mimeType | string | 
action\_result\.data\.\*\.results\.\*\.page\.ptr | string | 
action\_result\.data\.\*\.results\.\*\.page\.server | string | 
action\_result\.data\.\*\.results\.\*\.page\.status | string | 
action\_result\.data\.\*\.results\.\*\.page\.url | string |  `url` 
action\_result\.data\.\*\.results\.\*\.result | string |  `url` 
action\_result\.data\.\*\.results\.\*\.screenshot | string |  `url` 
action\_result\.data\.\*\.results\.\*\.stats\.consoleMsgs | numeric | 
action\_result\.data\.\*\.results\.\*\.stats\.dataLength | numeric | 
action\_result\.data\.\*\.results\.\*\.stats\.encodedDataLength | numeric | 
action\_result\.data\.\*\.results\.\*\.stats\.requests | numeric | 
action\_result\.data\.\*\.results\.\*\.stats\.uniqCountries | numeric | 
action\_result\.data\.\*\.results\.\*\.stats\.uniqIPs | numeric | 
action\_result\.data\.\*\.results\.\*\.task\.domain | string | 
action\_result\.data\.\*\.results\.\*\.task\.method | string | 
action\_result\.data\.\*\.results\.\*\.task\.source | string | 
action\_result\.data\.\*\.results\.\*\.task\.time | string | 
action\_result\.data\.\*\.results\.\*\.task\.url | string |  `url` 
action\_result\.data\.\*\.results\.\*\.task\.uuid | string | 
action\_result\.data\.\*\.results\.\*\.task\.visibility | string | 
action\_result\.data\.\*\.results\.\*\.uniq\_countries | numeric | 
action\_result\.data\.\*\.took | numeric | 
action\_result\.data\.\*\.total | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ip'
Find information about an IP address at urlscan\.io

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to lookup | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.has\_more | boolean | 
action\_result\.data\.\*\.results\.\*\.\_id | string | 
action\_result\.data\.\*\.results\.\*\.indexedAt | string | 
action\_result\.data\.\*\.results\.\*\.page\.asn | string | 
action\_result\.data\.\*\.results\.\*\.page\.asnname | string | 
action\_result\.data\.\*\.results\.\*\.page\.city | string | 
action\_result\.data\.\*\.results\.\*\.page\.country | string | 
action\_result\.data\.\*\.results\.\*\.page\.domain | string |  `domain` 
action\_result\.data\.\*\.results\.\*\.page\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.results\.\*\.page\.mimeType | string | 
action\_result\.data\.\*\.results\.\*\.page\.ptr | string | 
action\_result\.data\.\*\.results\.\*\.page\.server | string | 
action\_result\.data\.\*\.results\.\*\.page\.status | string | 
action\_result\.data\.\*\.results\.\*\.page\.url | string |  `url` 
action\_result\.data\.\*\.results\.\*\.result | string |  `url` 
action\_result\.data\.\*\.results\.\*\.screenshot | string |  `url` 
action\_result\.data\.\*\.results\.\*\.stats\.consoleMsgs | numeric | 
action\_result\.data\.\*\.results\.\*\.stats\.dataLength | numeric | 
action\_result\.data\.\*\.results\.\*\.stats\.encodedDataLength | numeric | 
action\_result\.data\.\*\.results\.\*\.stats\.requests | numeric | 
action\_result\.data\.\*\.results\.\*\.stats\.uniqCountries | numeric | 
action\_result\.data\.\*\.results\.\*\.stats\.uniqIPs | numeric | 
action\_result\.data\.\*\.results\.\*\.task\.domain | string | 
action\_result\.data\.\*\.results\.\*\.task\.method | string | 
action\_result\.data\.\*\.results\.\*\.task\.source | string | 
action\_result\.data\.\*\.results\.\*\.task\.time | string | 
action\_result\.data\.\*\.results\.\*\.task\.url | string |  `url` 
action\_result\.data\.\*\.results\.\*\.task\.uuid | string | 
action\_result\.data\.\*\.results\.\*\.task\.visibility | string | 
action\_result\.data\.\*\.results\.\*\.uniq\_countries | numeric | 
action\_result\.data\.\*\.took | numeric | 
action\_result\.data\.\*\.total | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate url'
Detonate a URL at urlscan\.io

Type: **investigate**  
Read only: **False**

If the get\_result parameter is set to true, then the action may take up to 2\-3 minutes to execute because the action will poll for the results in the same call\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to detonate | string |  `url`  `domain` 
**private** |  optional  | Run a private scan | boolean | 
**get\_result** |  optional  | Get scan result in same call | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.get\_result | boolean | 
action\_result\.parameter\.private | boolean | 
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.data\.\*\.api | string |  `url` 
action\_result\.data\.\*\.data\.console\.\*\.message\.column | numeric | 
action\_result\.data\.\*\.data\.console\.\*\.message\.level | string | 
action\_result\.data\.\*\.data\.console\.\*\.message\.line | numeric | 
action\_result\.data\.\*\.data\.console\.\*\.message\.source | string | 
action\_result\.data\.\*\.data\.console\.\*\.message\.text | string | 
action\_result\.data\.\*\.data\.console\.\*\.message\.url | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.data\.cookies\.\*\.expires | numeric | 
action\_result\.data\.\*\.data\.cookies\.\*\.httpOnly | boolean | 
action\_result\.data\.\*\.data\.cookies\.\*\.name | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.path | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.priority | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.sameParty | boolean | 
action\_result\.data\.\*\.data\.cookies\.\*\.sameSite | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.secure | boolean | 
action\_result\.data\.\*\.data\.cookies\.\*\.session | boolean | 
action\_result\.data\.\*\.data\.cookies\.\*\.size | numeric | 
action\_result\.data\.\*\.data\.cookies\.\*\.sourcePort | numeric | 
action\_result\.data\.\*\.data\.cookies\.\*\.sourceScheme | string | 
action\_result\.data\.\*\.data\.cookies\.\*\.value | string | 
action\_result\.data\.\*\.data\.globals\.\*\.prop | string | 
action\_result\.data\.\*\.data\.globals\.\*\.type | string | 
action\_result\.data\.\*\.data\.links\.\*\.href | string |  `url` 
action\_result\.data\.\*\.data\.links\.\*\.text | string | 
action\_result\.data\.\*\.data\.requests\.\*\.initiatorInfo\.host | string | 
action\_result\.data\.\*\.data\.requests\.\*\.initiatorInfo\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.initiatorInfo\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.documentURL | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.frameId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.hasUserGesture | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.columnNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.lineNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.stack\.callFrames\.\*\.columnNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.stack\.callFrames\.\*\.functionName | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.stack\.callFrames\.\*\.lineNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.stack\.callFrames\.\*\.scriptId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.stack\.callFrames\.\*\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.initiator\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.loaderId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.primaryRequest | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.encodedDataLength | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.fromPrefetchCache | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.\* | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Content\-Length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Content\-Type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Keep\-Alive | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Location | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Non\-Authoritative\-Reason | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Strict\-Transport\-Security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.Transfer\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.X\-DIS\-Request\-ID | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.access\-control\-allow\-credentials | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.access\-control\-allow\-origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.alt\-svc | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.cache\-control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.content\-length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.content\-type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.cross\-origin\-resource\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.expires | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.location | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.p3p | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.permissions\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.set\-cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.strict\-transport\-security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.timing\-allow\-origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.x\-content\-type\-options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.x\-frame\-options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.headers\.x\-xss\-protection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.mimeType | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.protocol | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.remoteIPAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.remotePort | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.\:authority | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.\:method | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.\:path | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.\:scheme | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Accept | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Accept\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Accept\-Language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Cache\-Control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Host | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Dest | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Mode | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Site | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Sec\-Fetch\-User | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.User\-Agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.accept | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.accept\-encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.accept\-language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.cache\-control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.sec\-fetch\-dest | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.sec\-fetch\-mode | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.sec\-fetch\-site | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.sec\-fetch\-user | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.upgrade\-insecure\-requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.requestHeaders\.user\-agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.responseTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.certificateId | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.certificateTransparencyCompliance | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.cipher | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.issuer | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.keyExchange | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.keyExchangeGroup | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.protocol | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.sanList | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.subjectName | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.validFrom | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityDetails\.validTo | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.securityState | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.status | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.statusText | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.connectEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.connectStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.dnsEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.dnsStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.proxyEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.proxyStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.pushEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.pushStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.receiveHeadersEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.requestTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.sendEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.sendStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.sslEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.sslStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.workerFetchStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.workerReady | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.workerRespondWithSettled | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.timing\.workerStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.redirectResponse\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.hasPostData | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.\* | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.Content\-Type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.Origin | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.Referer | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.User\-Agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.headers\.X\-Same\-Domain | string |  `domain` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.initialPriority | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.method | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.mixedContentType | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.postData | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.postDataEntries\.\*\.bytes | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.referrerPolicy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.request\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.request\.requestId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.timestamp | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.request\.wallTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.documentURL | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.frameId | string |  `md5` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.hasUserGesture | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.initiator\.columnNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.initiator\.lineNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.initiator\.stack\.callFrames\.\*\.columnNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.initiator\.stack\.callFrames\.\*\.functionName | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.initiator\.stack\.callFrames\.\*\.lineNumber | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.initiator\.stack\.callFrames\.\*\.scriptId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.initiator\.stack\.callFrames\.\*\.url | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.initiator\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.initiator\.url | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.loaderId | string |  `md5` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.asn | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.country | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.description | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.name | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.registrar | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.asn\.route | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.encodedDataLength | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.fromPrefetchCache | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.area | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.city | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.country | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.country\_name | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.eu | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.ll | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.metro | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.range | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.region | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.geoip\.timezone | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Cache\-Control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Content\-Language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Content\-Length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Content\-Security\-Policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Content\-Type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Keep\-Alive | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Location | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Non\-Authoritative\-Reason | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Set\-Cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Strict\-Transport\-Security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.Transfer\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.X\-DIS\-Request\-ID | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.X\-Frame\-Options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.X\-XSS\-Protection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.access\-control\-allow\-credentials | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.access\-control\-allow\-origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.alt\-svc | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.cache\-control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.content\-language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.content\-length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.content\-security\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.content\-type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.cross\-origin\-resource\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.expect\-ct | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.expires | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.location | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.p3p | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.permissions\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.referrer\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.set\-cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.strict\-transport\-security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.timing\-allow\-origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.x\-content\-type\-options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.x\-frame\-options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.headers\.x\-xss\-protection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.mimeType | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.protocol | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.rdns\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.rdns\.ptr | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.remoteIPAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.remotePort | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.\:authority | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.\:method | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.\:path | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.\:scheme | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Accept | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Accept\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Accept\-Language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Cache\-Control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Host | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Dest | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Mode | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Sec\-Fetch\-Site | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Sec\-Fetch\-User | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.User\-Agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.accept | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.accept\-encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.accept\-language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.cache\-control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.sec\-fetch\-dest | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.sec\-fetch\-mode | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.sec\-fetch\-site | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.sec\-fetch\-user | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.upgrade\-insecure\-requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.requestHeaders\.user\-agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.responseTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.certificateId | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.certificateTransparencyCompliance | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.cipher | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.issuer | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.keyExchange | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.keyExchangeGroup | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.protocol | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.sanList | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.subjectName | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.validFrom | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityDetails\.validTo | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.securityState | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.status | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.statusText | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.connectEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.connectStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.dnsEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.dnsStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.proxyEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.proxyStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.pushEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.pushStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.receiveHeadersEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.requestTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.sendEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.sendStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.sslEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.sslStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.workerFetchStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.workerReady | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.workerRespondWithSettled | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.timing\.workerStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.redirectResponse\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.headers\.Referer | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.headers\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.headers\.User\-Agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.initialPriority | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.method | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.mixedContentType | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.referrerPolicy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.request\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.requestId | string |  `md5` 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.requests\.\*\.wallTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.abp\.source | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.abp\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.abp\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.asn | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.country | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.description | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.name | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.registrar | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.asn\.route | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.dataLength | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.encodedDataLength | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.canceled | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.errorText | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.requestId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.timestamp | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.failed\.type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.area | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.city | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.country | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.country\_name | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.eu | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.ll | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.metro | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.range | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.region | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.timezone | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.geoip\.zip | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hash | string |  `sha256` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hashmatches\.\*\.file | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hashmatches\.\*\.project | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hashmatches\.\*\.project\_url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hashmatches\.\*\.source | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.hashmatches\.\*\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.rdns\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.rdns\.ptr | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.requestId | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.encodedDataLength | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.fromPrefetchCache | boolean | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.\* | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Accept\-Ranges | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Allow\-Credentials | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Allow\-Headers | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Allow\-Methods | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Allow\-Origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Expose\-Headers | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Access\-Control\-Max\-Age | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Age | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Alt\-Svc | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Cache\-Control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Content\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Content\-Length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Content\-Security\-Policy\-Report\-Only | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Content\-Type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.ETag | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Etag | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Expect\-CT | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Expires | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Keep\-Alive | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Last\-Modified | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.P3P | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Public\-Key\-Pins\-Report\-Only | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Referrer\-Policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Strict\-Transport\-Security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Timing\-Allow\-Origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Transfer\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Vary | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.Via | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Amz\-Cf\-Id | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Amz\-Cf\-Pop | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Cache | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Content\-Type\-Options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-DIS\-Request\-ID | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Frame\-Options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-LLID | string |  `md5` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-Powered\-By | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.X\-XSS\-Protection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.accept\-ranges | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.access\-control\-allow\-credentials | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.access\-control\-allow\-headers | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.access\-control\-allow\-method | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.access\-control\-allow\-methods | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.access\-control\-allow\-origin | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.access\-control\-expose\-headers | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.age | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.alt\-svc | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.ats\-carp\-promotion | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.cache\-control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-disposition | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-md5 | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-security\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-security\-policy\-report\-only | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.content\-type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.cross\-origin\-opener\-policy\-report\-only | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.cross\-origin\-resource\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.date | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.etag | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.expect\-ct | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.expires | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.last\-modified | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.link | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.p3p | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.public\-key\-pins\-report\-only | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.referrer\-policy | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.report\-to | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.server | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.set\-cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.status | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.strict\-transport\-security | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.timing\-allow\-origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.vary | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.via | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-amz\-cf\-id | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-amz\-cf\-pop | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-amz\-id\-2 | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-amz\-request\-id | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-amz\-server\-side\-encryption | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-cache | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-content\-type\-options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-fb\-content\-md5 | string |  `md5` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-fb\-debug | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-frame\-options | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-ua\-compatible | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.headers\.x\-xss\-protection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.mimeType | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.protocol | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.remoteIPAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.remotePort | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.\* | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.\:authority | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.\:method | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.\:path | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.\:scheme | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Accept | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Accept\-Encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Accept\-Language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Cache\-Control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Connection | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Host | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Referer | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Sec\-Fetch\-Dest | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Sec\-Fetch\-Mode | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Sec\-Fetch\-Site | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Sec\-Fetch\-User | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.User\-Agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.accept | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.accept\-encoding | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.accept\-language | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.cache\-control | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.content\-length | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.content\-type | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.cookie | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.origin | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.pragma | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.referer | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.sec\-fetch\-dest | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.sec\-fetch\-mode | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.sec\-fetch\-site | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.sec\-fetch\-user | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.upgrade\-insecure\-requests | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.user\-agent | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.requestHeaders\.x\-same\-domain | string |  `domain` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.responseTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.certificateId | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.certificateTransparencyCompliance | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.cipher | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.issuer | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.keyExchange | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.keyExchangeGroup | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.protocol | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.sanList | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.hashAlgorithm | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.logDescription | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.logId | string |  `sha256` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.origin | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.signatureAlgorithm | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.signatureData | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.status | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.signedCertificateTimestampList\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.subjectName | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.validFrom | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityDetails\.validTo | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityHeaders\.\*\.name | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityHeaders\.\*\.value | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.securityState | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.status | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.statusText | string | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.connectEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.connectStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.dnsEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.dnsStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.proxyEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.proxyStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.pushEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.pushStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.receiveHeadersEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.requestTime | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.sendEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.sendStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.sslEnd | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.sslStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.workerFetchStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.workerReady | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.workerRespondWithSettled | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.timing\.workerStart | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.response\.url | string |  `url` 
action\_result\.data\.\*\.data\.requests\.\*\.response\.size | numeric | 
action\_result\.data\.\*\.data\.requests\.\*\.response\.type | string | 
action\_result\.data\.\*\.data\.timing\.beginNavigation | string | 
action\_result\.data\.\*\.data\.timing\.domContentEventFired | string | 
action\_result\.data\.\*\.data\.timing\.frameNavigated | string | 
action\_result\.data\.\*\.data\.timing\.frameStartedLoading | string | 
action\_result\.data\.\*\.data\.timing\.frameStoppedLoading | string | 
action\_result\.data\.\*\.data\.timing\.loadEventFired | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.fieldErrors\.\*\.location | string | 
action\_result\.data\.\*\.fieldErrors\.\*\.msg | string | 
action\_result\.data\.\*\.fieldErrors\.\*\.param | string | 
action\_result\.data\.\*\.fieldErrors\.\*\.value | string | 
action\_result\.data\.\*\.lists\.asns | string | 
action\_result\.data\.\*\.lists\.certificates\.\*\.issuer | string | 
action\_result\.data\.\*\.lists\.certificates\.\*\.sanList | string | 
action\_result\.data\.\*\.lists\.certificates\.\*\.subjectName | string | 
action\_result\.data\.\*\.lists\.certificates\.\*\.validFrom | numeric | 
action\_result\.data\.\*\.lists\.certificates\.\*\.validTo | numeric | 
action\_result\.data\.\*\.lists\.countries | string | 
action\_result\.data\.\*\.lists\.domains | string | 
action\_result\.data\.\*\.lists\.hashes | string |  `sha256` 
action\_result\.data\.\*\.lists\.ips | string | 
action\_result\.data\.\*\.lists\.linkDomains | string | 
action\_result\.data\.\*\.lists\.servers | string | 
action\_result\.data\.\*\.lists\.urls | string |  `url` 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.meta\.processors\.abp\.data\.\*\.source | string | 
action\_result\.data\.\*\.meta\.processors\.abp\.data\.\*\.type | string | 
action\_result\.data\.\*\.meta\.processors\.abp\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.meta\.processors\.abp\.state | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.asn | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.country | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.date | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.description | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.name | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.registrar | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.data\.\*\.route | string | 
action\_result\.data\.\*\.meta\.processors\.asn\.state | string | 
action\_result\.data\.\*\.meta\.processors\.cdnjs\.data\.\*\.hash | string |  `sha256` 
action\_result\.data\.\*\.meta\.processors\.cdnjs\.data\.\*\.matches | string | 
action\_result\.data\.\*\.meta\.processors\.cdnjs\.state | string | 
action\_result\.data\.\*\.meta\.processors\.done\.data\.state | string | 
action\_result\.data\.\*\.meta\.processors\.done\.state | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.area | numeric | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.city | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.country | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.country\_name | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.eu | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.ll | numeric | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.metro | numeric | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.range | numeric | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.region | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.timezone | string | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.geoip\.zip | numeric | 
action\_result\.data\.\*\.meta\.processors\.geoip\.data\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.meta\.processors\.geoip\.state | string | 
action\_result\.data\.\*\.meta\.processors\.gsb\.state | string | 
action\_result\.data\.\*\.meta\.processors\.rdns\.data\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.meta\.processors\.rdns\.data\.\*\.ptr | string | 
action\_result\.data\.\*\.meta\.processors\.rdns\.state | string | 
action\_result\.data\.\*\.meta\.processors\.wappa\.state | string | 
action\_result\.data\.\*\.options\.useragent | string | 
action\_result\.data\.\*\.page\.asn | string | 
action\_result\.data\.\*\.page\.asnname | string | 
action\_result\.data\.\*\.page\.city | string | 
action\_result\.data\.\*\.page\.country | string | 
action\_result\.data\.\*\.page\.domain | string |  `domain` 
action\_result\.data\.\*\.page\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.page\.ptr | string | 
action\_result\.data\.\*\.page\.server | string | 
action\_result\.data\.\*\.page\.url | string |  `url` 
action\_result\.data\.\*\.result | string |  `url` 
action\_result\.data\.\*\.stats\.IPv6Percentage | numeric | 
action\_result\.data\.\*\.stats\.adBlocked | numeric | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.stats\.domainStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.index | numeric | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.initiators | string | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.ips | string | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.redirects | numeric | 
action\_result\.data\.\*\.stats\.domainStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.asn | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.country | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.date | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.description | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.name | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.registrar | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.asn\.route | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.count | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.domains | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.area | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.city | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.country | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.country\_name | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.eu | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.ll | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.metro | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.range | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.region | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.timezone | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.geoip\.zip | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.index | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.stats\.ipStats\.\*\.ipv6 | boolean | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.rdns\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.stats\.ipStats\.\*\.rdns\.ptr | string | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.redirects | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.requests | numeric | 
action\_result\.data\.\*\.stats\.ipStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.malicious | numeric | 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.ips | string | 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.protocol | string |  `url` 
action\_result\.data\.\*\.stats\.protocolStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.index | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.ips | string | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.redirects | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.regDomain | string |  `domain` 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.subDomains\.\*\.country | string | 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.subDomains\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.stats\.regDomainStats\.\*\.subDomains\.\*\.failed | boolean | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.compression | string | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.ips | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.latency | numeric | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.percentage | numeric | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.resourceStats\.\*\.type | string | 
action\_result\.data\.\*\.stats\.securePercentage | numeric | 
action\_result\.data\.\*\.stats\.secureRequests | numeric | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.ips | string | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.server | string | 
action\_result\.data\.\*\.stats\.serverStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.count | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.countries | string | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.encodedSize | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.ips | string | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.protocols\.QUIC /  / AES\_128\_GCM | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.protocols\.TLS 1\.2 / ECDHE\_ECDSA / AES\_128\_GCM | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.protocols\.TLS 1\.2 / ECDHE\_RSA / AES\_128\_GCM | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.protocols\.TLS 1\.3 /  / AES\_128\_GCM | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.protocols\.TLS 1\.3 /  / AES\_256\_GCM | numeric | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.securityState | string | 
action\_result\.data\.\*\.stats\.tlsStats\.\*\.size | numeric | 
action\_result\.data\.\*\.stats\.totalLinks | numeric | 
action\_result\.data\.\*\.stats\.uniqCountries | numeric | 
action\_result\.data\.\*\.status | numeric | 
action\_result\.data\.\*\.submitter\.country | string | 
action\_result\.data\.\*\.task\.domURL | string |  `url` 
action\_result\.data\.\*\.task\.method | string | 
action\_result\.data\.\*\.task\.options\.useragent | string | 
action\_result\.data\.\*\.task\.reportURL | string |  `url` 
action\_result\.data\.\*\.task\.screenshotURL | string |  `url` 
action\_result\.data\.\*\.task\.source | string | 
action\_result\.data\.\*\.task\.time | string | 
action\_result\.data\.\*\.task\.url | string |  `url` 
action\_result\.data\.\*\.task\.userAgent | string | 
action\_result\.data\.\*\.task\.uuid | string |  `urlscan submission id` 
action\_result\.data\.\*\.task\.visibility | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.verdicts\.community\.score | numeric | 
action\_result\.data\.\*\.verdicts\.community\.votesBenign | numeric | 
action\_result\.data\.\*\.verdicts\.community\.votesMalicious | numeric | 
action\_result\.data\.\*\.verdicts\.community\.votesTotal | numeric | 
action\_result\.data\.\*\.verdicts\.engines\.benignTotal | numeric | 
action\_result\.data\.\*\.verdicts\.engines\.enginesTotal | numeric | 
action\_result\.data\.\*\.verdicts\.engines\.maliciousTotal | numeric | 
action\_result\.data\.\*\.verdicts\.engines\.score | numeric | 
action\_result\.data\.\*\.verdicts\.overall\.hasVerdicts | numeric | 
action\_result\.data\.\*\.verdicts\.overall\.malicious | boolean | 
action\_result\.data\.\*\.verdicts\.overall\.score | numeric | 
action\_result\.data\.\*\.verdicts\.urlscan\.malicious | boolean | 
action\_result\.data\.\*\.verdicts\.urlscan\.score | numeric | 
action\_result\.data\.\*\.visibility | string | 
action\_result\.summary\.report\_uuid | string |  `urlscan submission id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 