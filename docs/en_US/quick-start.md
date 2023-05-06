# QuickStart

## Install from packagecloud source

### Install via AUR

- Nanomq basic edition

```bash
yay -S nanomq
```

- Nanomq sqlite edition

```bash
yay -S nanomq-sqlite
```

- Nanomq msquic edition

```bash
yay -S nanomq-msquic
```

- Nanomq full edition

```bash
yay -S nanomq-full
```

### Install via DEB source

```shell
curl -s https://assets.emqx.com/scripts/install-nanomq-deb.sh | sudo bash
sudo apt-get install nanomq
```

### Install Deb package manually 
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



### Install via RPM source

```shell
curl -s https://assets.emqx.com/scripts/install-nanomq-rpm.sh | sudo bash
sudo yum install -y nanomq
```

### Install RPM package manually 

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

## Compile & Install

To build NanoMQ, you will need a C99 compatible compiler and [CMake](https://www.cmake.org/) version 3.13 or newer.

Basically, you need to compile and install NanoMQ by following steps :

```bash
$ mkdir build
$ cd build
$ cmake -G Ninja ..
$ sudo ninja install
```

Or you can compile it without ninja:

```bash
$ mkdir build 
$ cd build
$ cmake .. 
$ make
```

Add `NNG_ENABLE_TLS` to enable **TLS**:
>[mbedTLS](https://tls.mbed.org) needs to be installed first.
```bash
cmake -G Ninja -DNNG_ENABLE_TLS=ON ..
```
or
```bash
cmake -DNNG_ENABLE_TLS=ON ..
```
> View config file `nanomq.conf` for more parameters about TLS.

## Start MQTT Broker

```bash
nanomq start
```

Currently, NanoMQ supports MQTT 3.1.1 & 5.0, MQTT 3.1 is not included



## MQTT Client

```bash
# Publish
nanomq_cli pub --url <url> -t <topic> -m <message> [--help]

# Subscribe
nanomq_cli sub --url <url> -t <topic> [--help]

# Connect*
nanomq_cli conn --url <url> [--help]
```
