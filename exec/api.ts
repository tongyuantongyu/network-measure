// Request JSON type definition

// Without special note, all time in these API are in millisecond

// `stamp` is the unix time stamp when sending the request in second.
// This tool only handle request if stamp is within 60 seconds.
// `nonce` is a random number that should only use once.
// This tool will refuse to handle the request if the attached
// nonce was used in 60 seconds.

export interface ResolveQ {
  address: string; // fqdn to perform name resolve
  family: number;  // IP family. 4, 6 or 0(auto)
  wait: number;    // wait time for doing resolve
  stamp: number;
  nonce: number;
}

export interface PingQ {
  address: string;  // IP or domain to ping
  family: number;   // IP family. 4, 6 or 0(auto)
  wait: number;     // wait time to receive icmp response
  interval: number; // Interval between received icmp response / determined timeout and send next icmp echo
  times: number;    // number of icmp echo to send
  stamp: number;
  nonce: number;
}

export interface TCPingQ {
  address: string;  // IP or domain to tcping
  family: number;   // IP family. 4, 6 or 0(auto)
  port: number;     // Port to connect
  wait: number;     // Wait time before timeout
  interval: number; // interval between connected / determined timeout and next try
  times: number;    // number of tcp connect to make
  stamp: number;
  nonce: number;
}

export interface MtrQ {
  address: string;  // IP or domain to mtr
  family: number;   // IP family. 4, 6 or 0(auto)
  wait: number;     // Wait time before timeout
  interval: number; // interval between sending two icmp echo
  times: number;    // number of probing to make
  max_hop: number;  // max number of hops to probe
  rdns: boolean;    // do rdns lookup
  stamp: number;
  nonce: number;
}

export interface SpeedQ {
  url: string;      // url to send HTTP request
  family: number;   // IP family. 4, 6 or 0(auto)
  wait: number;     // Wait time before timeout
  span: number;     // time span for receiving
  interval: number; // minimal interval between sample point
  stamp: number;
  nonce: number;
}

// Response JSON type definition

export interface Response {
  ok: boolean;
  info?: string; // error message. only available when ok is false
  result?: ResolveP | PingP | TCPingP | MtrP | SpeedP; // data corresponding to request type.
                                                       // only available when ok is true
}

export interface ResolveP {
  data: string[] | null; // resolved addresses
}

export interface PingP {
  resolved: string; // ip selected to ping on
  data: {
    ip: string;      // the ip sending icmp response
    code: number;    // code of icmp response (see below for code definition)
    latency: number; // latency between send and recv
  }[] | null;
}

export interface TCPingP {
  resolved: string; // ip selected to tcping on
  data: {
    success: boolean; // connect succeed
    latency: number;  // latency used on connect target
  }[] | null;
}

export interface MtrPEntry {
  address: string; // the ip sending icmp response
  rdns: string;    // rdns of ip
  code: number;    // code of icmp response (see below for code definition)
  latency: number; // latency between send and recv
}

export interface MtrP {
  resolved: string; // ip selected to mtr
  data: (MtrPEntry[] | null)[];
}


export interface SpeedP {
  resolved: string; // ip selected to send request
  latency: number;  // latency to establish http connection
  elapsed: number;  // total download time
  received: number; // total received data
  data: {
    point: number;    // time point from begin
    received: number; // received data from last sample point
  }[] | null;
}

// Meaning of code of icmp response

// 0:   Network unreachable
// 1:   Host unreachable
// 2:   Protocol unreachable
// 3:   Port unreachable
// 4:   Datagram too big
// 5:   Source route failed
// 6:   Destination network unknown
// 7:   Destination host unknown
// 8:   Source host isolated
// 9:   Destination network administratively prohibited
// 10:  Destination host administratively prohibited
// 11:  Network unreachable for Type Of Service
// 12:  Host unreachable for Type Of Service
// 13:  Communication Administratively Prohibited
// 14:  Host precedence violation
// 15:  Precedence cutoff in effect

// if code is one of above, then the received message is of type DestinationUnreachable

// 256: Timeout               // no response received within wait time
// 257: Received EchoReply    // received a message of type EchoReply
// 258: Received TimeExceed   // received a message of type TimeExceed