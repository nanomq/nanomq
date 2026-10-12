# Listener 

The Listener configuration allows you to specify settings for different types of connections that your NanoMQ broker can accept. There are four types of listeners: TCP Listener, SSL Listener, WebSocket Listener, and Secure WebSocket Listener.

## MQTT/TCP Listener - 1883

### **Example Configuration**

```hcl
listeners.tcp {
  bind = "0.0.0.0:1883"     # The listener binds to all network interfaces on port 1883
}

listeners.tcp.listener_1 {
  bind = "0.0.0.0:1884"     # The listener binds to all network interfaces on port 1884
}

listeners.tcp.listener_2 {
  bind = "0.0.0.0:1885"     # The listener binds to all network interfaces on port 1885
}
```
NanoMQ support multi-listeners now. 

### **Configuration Items**

- `bind`: Specifies the IP address and port that the TCP listener should bind to. The value should be in the format `<ip:port>`.

## MQTT/SSL Listener - 8883

### **Example Configuration**

```hcl
listeners.ssl {
  bind = "0.0.0.0:8883"              # Bind to all network interfaces on port 8883
  # key_password = <yourpass>        # String with the password to decrypt private keyfile
  keyfile = "/etc/certs/key.pem"     # Key file path
  certfile = "/etc/certs/cert.pem"   # User certificate file path
  cacertfile = "/etc/certs/cacert.pem" # CA certificate file path
  verify_peer = false					  		 # If NanoMQ requests a certificate from the client 	
  fail_if_no_peer_cert = false			 # If to reject connection if no certificate is provided
  # Set verify_peer = true before enabling certificate usernames.
  # peer_cert_as_username = cn       # Use the client certificate's CN as the MQTT username
}
```

### **Configuration Items**

- `bind`: Specifies the IP address and port that the SSL listener should bind to.
- `key_password`: A string that contains the password needed to decrypt the private keyfile, only needed if the private keyfile has been encrypted with a password. 
- `keyfile`: Specifies the path to the SSL key file that contains the user's private PEM-encoded key.
- `certfile`: Specifies the path to the file that contains the user certificate.
- `cacertfile`: Specifies the path to the file that contains the PEM-encoded CA certificates.
- `verify_peer`: Specifies whether the server requests a certificate from the client, optional value: 
  - `true`: verify_peer
  - `false `: verify_none
- `fail_if_no_peer_cert`: Specifies whether to deny the connection if no certificate is provided, valid only when `verify_peer` is set to true, optional values: 
  - `true`: Rejects the connection if the client sends an empty certificate.
  - `false`: Rejects the connection only when the client sends an invalid certificate.
- `peer_cert_as_username`: Sets the MQTT username from the client certificate instead of the CONNECT packet. Optional values:
  - `disable` (default): Keep the username sent by the client.
  - `cn`: Use the first common name (CN) attribute of the client certificate subject. It must be a UTF8String, PrintableString or IA5String without NUL characters.
  - `dn`: Use the full subject distinguished name of the client certificate. The format depends on the TLS engine: mbedTLS gives `C=SE, O=Example, CN=alice`, OpenSSL gives the RFC 2253 form `CN=alice,O=Example,C=SE`.

  Requires `verify_peer = true`; NanoMQ refuses to start otherwise, because no client certificate would be requested. When enabled, the username and password sent by the client are discarded, and the connection is refused as not authorized unless the client presented a certificate that was verified against `cacertfile` and carries the selected field. The verified certificate replaces the username/password check; HTTP authentication still runs and receives the certificate username as `%u`, so it can apply further policy. With `fail_if_no_peer_cert = true`, clients without a valid certificate are already rejected during the TLS handshake. Like the other TLS settings, the secure WebSocket listener uses the value from the single `listeners.ssl` block.

## MQTT/WebSocket Listener - 8083

### **Example Configuration**

```hcl
listeners.ws {
  bind = "0.0.0.0:8083/mqtt"			# Bind to all network interfaces on port 8083
}
```

### **Configuration Items**

- `bind`: Specifies the IP address and port that the WebSocket listener should bind to.

## MQTT/Secure WebSocket Listener - 8084

### **Example Configuration**

```hcl
listeners.wss {
  bind = "0.0.0.0:8084"           	# Bind to all network interfaces on port 8084
}
```

### **Configuration Items**

- `bind`: Specifies the IP address and port that the Secure WebSocket listener should bind to.

::: tip

The secure WebSocket listener utilizes the same `keyfile`, `certfile`, and `cacertfile` as the SSL listener. Therefore, if these certificate-related items have already been set for the SSL listener, there is no need to configure them again for the secure WebSocket listener. However, if no SSL listener has been configured, you will need to set the following configurations for the secure WebSocket listener:

- `keyfile`
- `certfile`
- `cacertfile`

:::
