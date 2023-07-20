# Listener 

The Listener configuration allows you to specify settings for different types of connections that your NanoMQ broker can accept. There are four types of listeners: TCP Listener, SSL Listener, WebSocket Listener, and Secure WebSocket Listener.

## TCP Listener

**Example Configuration**

```hcl
listeners.tcp.tcp_listener_1 = {
  bind = "0.0.0.0:1883"     # The listener binds to all network interfaces on port 1883
}
```

**Configuration Items**

- `bind`: Specifies the IP address and port that the TCP listener should bind to. The value should be in the format `<ip:port>`.

## SSL Listener

**Example Configuration**

```hcl
listeners.ssl.<listener-name> = {
  bind = "0.0.0.0:8883"              # Bind to all network interfaces on port 8883
  # key_password = <yourpass>        # String with the password to decrypt private keyfile
  keyfile = "/etc/certs/key.pem"     # Key file path
  certfile = "/etc/certs/cert.pem"   # User certificate file path
  cacertfile = "/etc/certs/cacert.pem" # CA certificate file path
  verify_peer = false					  		 # If NanoMQ requests a certificate from the client 	
  fail_if_no_peer_cert = false			 # If to reject connection if no certificate is provided
}
```

**Configuration Items**

- `bind`: Specifies the IP address and port that the SSL listener should bind to.
- `key_password`: A string that contains the password needed to decrypt the private keyfile, only needed if the private keyfile has been encrypted with a password. 
- `keyfile`: Specifies the path to the SSL key file that contains the user's private PEM-encoded key.
- `certfile`: Specifies the path to the file that contains the user certificate.
- `cacertfile`: Specifies the path to the file that contains the PEM-encoded CA certificates.
- `verify_peer`: Specifies whether the server requests a certificate from the client, optional value: 
  - `true`: verify_peer
  - `false ` verify_none
- `fail_if_no_peer_cert`: Specifies whether to deny the connection if no certificate is provided, valid only when `verify_peer` is set to true, optional values: 
  - `true`: Rejects the connection if the client sends an empty certificate.
  - `false`: Rejects the connection only when the client sends an invalid certificate.

## WebSocket Listener

**Example Configuration**

```hcl
listeners.ws.<listener-name> = {
  bind = "0.0.0.0:8083/mqtt"			# Bind to all network interfaces on port 8883
}
```

**Configuration Items**

- `bind`: Specifies the IP address and port that the WebSocket listener should bind to.

## Secure WebSocket Listener

**Example Configuration**

```hcl
listeners.wss.<listener-name> = {
  bind = "0.0.0.0:8084"           	# Bind to all network interfaces on port 8883
}
```

**Configuration Items**

- `bind`: Specifies the IP address and port that the Secure WebSocket listener should bind to.

::: tip

The secure WebSocket listener utilizes the same `keyfile`, `certfile`, and `cacertfile` as the SSL listener. Therefore, if these certificate-related items have already been set for the SSL listener, there is no need to configure them again for the secure WebSocket listener. However, if no SSL listener has been configured, you will need to set the following configurations for the secure WebSocket listener:

- `keyfile`
- `certfile`
- `cacertfile`

:::