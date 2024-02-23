# SSL/TLS

SSL: (Secure Socket Layer) is a protocol layer situated between reliable connection-oriented network layer protocols and application layer protocols. SSL ensures secure communication between clients and servers through mutual authentication, the use of digital signatures for integrity, and encryption for privacy. The protocol consists of two layers: the SSL Record Protocol and the SSL Handshake Protocol.

TLS: (Transport Layer Security) provides confidentiality and data integrity between two communicating applications. This protocol also consists of two layers: the TLS Record Protocol and the TLS Handshake Protocol.

## Advantages of SSL/TLS

1. **Encryption**: TLS and SSL encrypt data transmitted between clients and servers, ensuring privacy and security during transmission. This means only the sender and receiver can interpret the transmitted information, preventing man-in-the-middle attacks.
2. **Authentication**: By using certificates, TLS and SSL offer a mechanism to authenticate the identity of the parties, ensuring you are communicating with the intended server or client. This helps prevent deception and information leakage.
3. **Data Integrity**: TLS and SSL can detect if data has been tampered with during transmission. If data is illegally modified, the receiving party can detect this through a failed verification, thus ensuring data integrity.
4. **Adaptability and Compatibility**: The TLS protocol supports various encryption algorithms, allowing the communicating parties to negotiate the strongest common encryption method. Moreover, they are widely supported across different devices and operating systems.
5. **Trust Mechanism**: By trusting known and authoritative Certificate Authorities (CA), TLS and SSL can establish a secure chain of trust, further enhancing the security of network communication.

Although SSL is no longer recommended due to vulnerabilities found in several versions, TLS continues to evolve and has replaced SSL as the standard method for securing network communication.

## SSL/TLS One-way Authentication

SSL/TLS One-way authentication is the most common authentication method, mainly used for client verification of server identity, ensuring the client connects with the genuine server rather than a forged one. This method is very common in internet communication, especially when accessing secure websites (such as those using the HTTPS protocol).

### Advantages and Limitations

- **Advantages**: One-way authentication simplifies the authentication process and reduces configuration complexity, making it very suitable for most client-server model scenarios, like web browsers accessing websites.
- **Limitations**: One-way authentication only verifies the server's identity, not the client's. This means any client can establish a connection with the server, potentially introducing security risks, such as preventing unauthorized client access.

For scenarios requiring higher security, such as financial services or the exchange of sensitive information, two-way SSL/TLS authentication may be necessary, simultaneously verifying the identity of both client and server to ensure mutual trust and security.

## SSL/TLS two-way Authentication

Two-way authentication requires certificates from both the server and the client for communication authentication, ensuring that both parties involved in the communication are trusted. Both parties share their public certificates and then perform verification based on those certificates. Some applications requiring high security levels necessitate enabling bilateral SSL/TLS authentication.

### Main Features

1. **Mutual Identity Verification**: Not only does the server need to provide a certificate to prove its identity to the client, but the client also needs to provide a certificate to the server to prove its identity.
2. **Enhanced Security**: By ensuring the identity of both communication parties, two-way authentication offers a higher level of security than One-way authentication.
3. **Applicable to Sensitive Transactions**: Suitable for scenarios requiring high security, such as banks and financial institutions, medical information systems, etc.

### Advantages

- Provides a higher level of security since both parties must prove their identity.
- Suitable for applications requiring high security, such as online banking, e-commerce platforms, and private networks.

### Limitations

- More complex configuration, requiring valid certificates for both client and server.
- May increase costs, as client certificates typically need to be purchased and maintained from authoritative CAs.
- The usage process might be more cumbersome for users, especially when client certificates need to be regularly updated or replaced.

## Differences Between one-way and two-way Authentication

### Authentication Process

- **One-way Authentication**: Only the server needs to prove its identity to the client. The client achieves this by verifying the server's certificate issued by a trusted Certificate Authority. This is the most common scenario, such as when accessing an HTTPS website via a browser.
- **Two-way Authentication**: Both server and client must mutually verify each other's identity. This means that in addition to the server providing a certificate for the client to verify, the client must also provide a certificate for the server to verify. This method is typically used in scenarios requiring a high level of security, such as internal networks and financial transactions.

## Generating Server and Client Certificates with OpenSSL

### 1. Generate a Self-Signed CA Certificate
- Generate a Private Key
``` shell
# Run the following command to generate an RSA private key:
openssl genrsa -out ca.key 2048
```

- Generate a Self-Signed CA Certificate
``` shell
# Use the following command to generate a self-signed CA certificate:
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem
```
During the certificate generation process, OpenSSL will prompt you to enter the certificate's subject information, such as Country, State/Province, City, Organization, Organizational Unit, Common Name (the name of the CA), and Email Address. Enter the relevant information as prompted.

### 2. Generate a Server Certificate
- Generate the Server's Private Key
``` shell
# First, generate an RSA private key for the server:
openssl genrsa -out server.key 2048
```

- Create a Certificate Signing Request for the Server
``` shell
# Use the server's private key to create a CSR:
openssl req -new -key ./server.key -out server.csr
```

- Issue a Server Certificate using the Self-Signed CA Certificate
``` shell
# Now, use the CA certificate and private key generated in the first step to issue a server certificate:
openssl x509 -req -in ./server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 3650 -sha256
```

### 3. Generate a Client Certificate
The process of generating a client certificate is similar to generating a server certificate:
- Generate the Client's Private Key
``` shell
# First, generate an RSA private key for the client:
openssl genrsa -out client-key.pem 2048
```

- Create a Certificate Signing Request for the Client
``` shell
openssl req -new -key client-key.pem -out client.csr
```

- Issue a Client Certificate using the Self-Signed CA Certificate
``` shell
openssl x509 -req -days 3650 -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem
```

## NanoMQ's Two-way Authentication Bridge

NanoMQ provides configuration options for two-way authentication to bridge to a remote server. The required steps are simple, only requiring the addition of certificates in the configuration file's bridge section, as shown in the example below:

```bash
# nanomq.conf
...
bridges.mqtt.emqx1 {
...
# # Ssl config ##
     ssl {
        # # Ssl key password
        # # String containing the user's password. Only used if the private keyfile
        # # is password-protected.
        # #
        # # Value: String
        key_password = "yourpass"
        # # Ssl keyfile
        # # Path of the file containing the client's private key.
        # #
        # # Value: File
        keyfile = "/etc/certs/key.pem"
        # # Ssl cert file
        # # Path of the file containing the client certificate.
        # #
        # # Value: File
        certfile = "/etc/certs/cert.pem"
        # # Ssl ca cert file
        # # Path of the file containing the server's root CA certificate.
        # #
        # # Value: File
        cacertfile = "/etc/certs/cacert.pem"
    }
...
```
