# Behavior for Websocket-based Network measure

1. This instance starts HTTP connection with headers:

```
X-Identifier: (instance name).(current time).(nonce)
X-Signature: hex-encoded HMAC-SHA256 for X-Identifier
```

2. Server does a series of check to the connection:

    - Server SHALL check the signature is valid, otherwise the connection SHALL be 
closed immediately.

    - Upon check pass, server SHALL check the time span from the timestamp in
Identifier to server current time is within a specific range (say span A),
otherwise the connection SHALL be closed immediately.

    - Then the nonce SHALL be recorded and connection within such a span A using the
same nonce SHALL be closed immediately.

3. Perform connection upgrade and establish websocket connection

4. This instance sends websocket ping message every 10 seconds and server should
responses websocket pong message upon receiving ping message.
   
5. Server sends command to this instance. Request should be in following format:

    ```
    [u32be type][u32be length][byte[length] parameter]
    ```

   where `type` maps to:

    ```
    0: Resolve
    1: Ping
    2: TCPing
    3: MTR
    4: Speed
    ```

   The parameter should be json with following schema:
    ```typescript
    export interface Request {
        id: number;
        request: ResolveQ | PingQ | TCPingQ | MtrQ | SpeedQ;
    }
    ```
   
   where the `id` is an 64 bit unsigned integer as an identifier to this 
   request.
   
6. This instance processes command, and return result in following format:
    ```
    [u32be type][u32be length][byte[length] response]
    ```
   where `type` is the type of command.

   The response will be json with following schema:

   ```typescript
   export interface Response {
     id: number;
     ok: boolean;
     info?: string;
     result?: ResolveP | PingP | TCPingP | MtrP | SpeedP;
   }
   ```
   
7. The connection should not be closed after command finished.