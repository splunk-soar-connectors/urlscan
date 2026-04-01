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
