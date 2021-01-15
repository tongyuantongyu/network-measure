# (Remote) Network Measure Tool

This tool helps you to get network information from a remote network environment,
by setting up an HTTP server and provides JSON APIs.

## Abilities

### Resolve

Perform a name resolve at remote, and get all resolved IP Address back.

### Ping

Perform a number of ICMP Ping and get information of received response and latency info.

### TCPing

Perform a number of TCP Ping (connect) and get information of connect result and latency info.

### MTR

Perform MTR (Multi traceroute) by sending ICMP Ping with ascending TTL, and get
information of received response and latency info.

### Speed test

Send HTTP GET request and receive response for a given amount of time. Measure
HTTP connection latency, size of data received in each interval
as well as total received size of data.

## API

See `api.ts` for definition of request and response JSON data and meaning.

## Config

Copy `config.example.toml` as `config.toml`. Read the comment to understand
meaning of each config item.