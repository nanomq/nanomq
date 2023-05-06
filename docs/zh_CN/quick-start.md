# 快速开始

## 源安装

### AUR 一键安装

- Nanomq 基础版

```bash
yay -S nanomq
```

- Nanomq sqlite 版

```bash
yay -S nanomq-sqlite
```

- Nanomq msquic 版

```bash
yay -S nanomq-msquic
```

- Nanomq full 版

```bash
yay -S nanomq-full
```

### Deb 一键安装

```shell
curl -s https://assets.emqx.com/scripts/install-nanomq-deb.sh | sudo bash
sudo apt-get install nanomq
```

### Deb 手动安装
```shell
sudo bash -c 'cat << EOF > /etc/apt/sources.list.d/emqx_nanomq.list
deb [signed-by=/usr/share/keyrings/emqx_nanomq-archive-keyring.gpg] https://packages.emqx.com/emqx/nanomq/any/ any main
deb-src [signed-by=/usr/share/keyrings/emqx_nanomq-archive-keyring.gpg] https://packages.emqx.com/emqx/nanomq/any/ any main
EOF'

gpg_key_url="https://packages.emqx.com/emqx/nanomq/gpgkey"
gpg_keyring_path="/usr/share/keyrings/emqx_nanomq-archive-keyring.gpg"
curl -fsSL "${gpg_key_url}" | gpg --dearmor > ${gpg_keyring_path}
mv ${gpg_keyring_path} /etc/apt/trusted.gpg.d/emqx_nanomq.gpg

sudo apt-get update
sudo apt-get install nanomq
```

### Rpm 一键安装

```shell
curl -s https://assets.emqx.com/scripts/install-nanomq-rpm.sh | sudo bash
sudo yum install -y nanomq
```

### Rpm 手动安装

```shell
sudo bash -c 'cat << EOF > /etc/yum.repos.d/emqx_nanomq.repo
[emqx_nanomq]
name=emqx_nanomq
baseurl=https://packages.emqx.com/emqx/nanomq/rpm_any/rpm_any/$basearch
repo_gpgcheck=1
gpgcheck=0
enabled=1
gpgkey=https://packages.emqx.com/emqx/nanomq/gpgkey
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300
EOF'

sudo yum -q makecache -y --disablerepo='*' --enablerepo='emqx_nanomq'
sudo yum install -y nanomq
```

## Docker安装

```
docker run -d --name nanomq emqx/nanomq:0.10.5
```
指定配置文件启动
```
docker run -d -p 1883:1883 -v {YOU LOCAL PATH}: /etc \
            --name nanomq  emqx/nanomq:0.10.5
```
详细Docker配置方式请参阅Readme文档

## 编译安装

编译 NanoMQ 需要支持 C99 标准的编译环境和高于 3.13 的 [CMake](https://cmake.org/) 版本。

您可以通过以下步骤来编译和安装 NanoMQ：

```bash
$ mkdir build
$ cd build
$ cmake -G Ninja ..
$ sudo ninja install
```

或者你可以不用 ninja 来编译：

```bash
$ mkdir build 
$ cd build
$ cmake .. 
$ make
```

可增加 cmake 编译参数 `NNG_ENABLE_TLS` 来支持 **TLS** 连接:
>需提前安装 [mbedTLS](https://tls.mbed.org).
```bash
cmake -G Ninja -DNNG_ENABLE_TLS=ON ..
```
或者
```bash
cmake -DNNG_ENABLE_TLS=ON ..
```
> 查看配置文件 `nanomq.conf` 了解更多TLS相关配置参数.

## 编译依赖

请注意，NanoMQ 依赖于nng

依赖项可以独立编译

```bash
$PROJECT_PATH/nanomq/nng/build$ cmake -G Ninja ..
$PROJECT_PATH/nanomq/nng/build$ ninja install
```


## 启动 MQTT Broker

```bash
nanomq start &
```

目前，NanoMQ完整支持MQTT 3.1.1和部分MQTT 5.0协议。



## 使用MQTT Client

```bash
# Publish
nanomq_cli pub --url <url> -t <topic> -m <message> [--help]

# Subscribe
nanomq_cli sub --url <url> -t <topic> [--help]

# Connect*
nanomq_cli conn --url <url> [--help]
```
