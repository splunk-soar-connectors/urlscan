The **api_key** field is not required to use this app, as **urlscan.io** does not require an API key
for querying its database. However, if you wish to start a scan with **detonate url** , then you
will need an API key configured. The **lookup malicious domain** action requires a **urlscan Pro**
API key configured on the asset.

## Malicious Domain Lookup

The **lookup malicious domain** action calls `GET /api/v1/malicious/domain/{domain}` for an
apex/registered domain (for example, `example.com`); the lookup covers the domain and all of
its subdomains. It returns
`observable`, `type`, `count`, `firstSeen`, and `lastSeen`. The action summary exposes `count`,
`first_seen`, and `last_seen` for use in playbooks. The timestamps may be null when no malicious
scan history exists. A zero count does not establish that a domain is safe.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Urlscan server. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |
