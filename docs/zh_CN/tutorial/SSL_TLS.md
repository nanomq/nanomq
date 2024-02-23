# SSL/TLS

SSL:（Secure Socket Layer，安全套接字层），位于可靠的面向连接的网络层协议和应用层协议之间的一种协议层。SSL通过互相认证、使用数字签名确保完整性、使用加密确保私密性，以实现客户端和服务器之间的安全通讯。该协议由两层组成：SSL记录协议和SSL握手协议。

TLS：(Transport Layer Security，传输层安全协议)，用于两个应用程序之间提供保密性和数据完整性。该协议由两层组成：TLS记录协议和TLS握手协议。

## SSL/TLS优点

1. **加密**：TLS和SSL可以加密客户端和服务器之间传输的数据，确保数据传输过程中的隐私和安全。这意味着只有发送和接收方能够解读传输的信息，防止中间人攻击。
2. **身份验证**：通过使用证书，TLS和SSL提供了一种机制来验证对方的身份，确保你正在与预期的服务器或客户端通信。这有助于防止欺骗和信息泄露。
3. **数据完整性**：TLS和SSL能够检测数据在传输过程中是否被篡改。如果数据被非法修改，接收方能够通过验证失败来检测到，从而确保数据的完整性。
4. **适应性和兼容性**：TLS协议支持多种加密算法，允许参与通信的双方协商出一个共同支持的最强加密方法。此外，它们广泛被支持，在多种设备和操作系统上都可以使用。
5. **信任机制**：通过信任已知和权威的证书颁发机构（CA），TLS和SSL能够建立起一个安全的信任链，进一步增强了网络通信的安全性。

虽然SSL现在已经不再被推荐使用，因为它的多个版本已经被证明存在安全漏洞，TLS继续发展并取代了SSL，成为保护网络通信的标准方法。

## SSL/TLS单向认证

SSL/TLS单向认证是最常见的认证方式，主要用于客户端验证服务器的身份，确保客户端与真正的服务器而非伪造的服务器建立连接。这种方法在互联网通信中非常普遍，尤其是在浏览器访问安全网站（如使用HTTPS协议的网站）时。

### **优点和局限性**

- **优点**：单向认证简化了认证过程，减少了配置的复杂性，非常适合大多数客户端-服务器模型的应用场景，如Web浏览器访问网站。
- **局限性**：单向认证只验证服务器的身份，不验证客户端的身份。这意味着任何客户端都可以与服务器建立连接，可能会引入一些安全风险，例如无法防止未授权的客户端访问。

对于需要更高安全性的场景，例如金融服务或敏感信息的交换，可能需要使用双向SSL/TLS认证，这种方式同时验证客户端和服务器的身份，确保双向的信任和安全。

## **SSL/TLS 双向认证**

双向认证是指在进行通信认证时要求服务端和客户端都需要证书，双方都要进行身份认证，以确保通信中涉及的双方都是受信任的。 双方彼此共享其公共证书，然后基于该证书执行验证、确认。一些对安全性要求较高的应用场景，就需要开启双向 SSL/TLS 认证。

### **主要特点**

1. **双方身份验证**：不仅服务器需要向客户端提供证书证明其身份，客户端也需要提供证书给服务器，以证明其身份。
2. **增强的安全性**：通过确保通信双方的身份，双向认证提供了比单向认证更高级别的安全保障。
3. **适用于敏感交易**：适合那些需要高度安全保障的场景，例如银行和金融机构、医疗信息系统等。

### **优点**

- 提供了比单向认证更高的安全级别，因为双方都必须证明自己的身份。
- 适合于对安全性要求极高的应用场景，如在线银行、电子商务平台和私有网络。

### **局限性**

- 配置更为复杂，需要客户端和服务器都具备有效的证书。
- 可能会增加成本，因为客户端证书通常需要从权威的CA处购买和维护。
- 对用户来说，使用过程可能会更加繁琐，特别是在客户端证书需要定期更新或替换的情况下。

## 单向认证和双向认证的区别

### **认证过程**

- **单向认证**：只有服务器需要向客户端证明其身份。客户端通过验证服务器提供的证书（由可信的证书颁发机构签发）来实现这一点。这是最常见的使用场景，例如，当你通过浏览器访问一个HTTPS网站时。
- **双向认证**：服务器和客户端都必须互相验证对方的身份。这意味着除了服务器需要提供证书给客户端验证外，客户端也必须提供证书给服务器进行验证。这种方式通常用在需要高安全级别的场景中，如内部网络、金融交易等。

## 使用openssl生成服务端和客户端证书

### 1. 生成自签名CA证书
- 生成私钥
``` shell
# 运行以下命令生成RSA私钥：
openssl genrsa -out ca.key 2048
```

- 生成自签名的CA证书
``` shell
# 使用以下命令生成自签名的CA证书：
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem
```
在生成证书的过程中，openssl会提示你输入证书的主题信息，如国家（Country）、省份（State）、城市（Locality）、组织（Organization）、组织单位（Organizational Unit）、常用名称（Common Name，即CA的名字）和电子邮件地址。根据提示输入相应信息即可。


### 2. 生成服务端证书
- 生成服务器的私钥
``` shell
# 首先，为服务器生成一个RSA私钥
openssl genrsa -out server.key 2048
```

- 创建服务器的证书签名请求
``` shell
# 使用服务器的私钥创建一个CSR
openssl req -new -key ./server.key -out server.csr
```

- 使用自签名的CA证书签发服务器证书
``` shell
# 现在，使用第一步中生成的CA证书和私钥来签发服务器证书。
openssl x509 -req -in ./server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 3650 -sha256
```

### 3. 生成客户端证书
生成客户端证书的过程与生成服务器证书类似：

- 生成客户端的私钥
``` shell
# 首先，为客户端生成一个RSA私钥：
openssl genrsa -out client-key.pem 2048
```

- 创建客户端的证书签名请求
``` shell
openssl req -new -key client-key.pem -out client.csr
```

- 使用自签名的CA证书签发客户端证书
``` shell
openssl x509 -req -days 3650 -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem
```

## NanoMQ通过SSL/TLS双向认证桥接

NanoMQ提供了双向认证的配置选项桥接到远端服务器。所需步骤也很简单，仅需要在配置文件中的桥接字段中新增证书即可，以下是示例：

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
