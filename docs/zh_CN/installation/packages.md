# 使用安装包源安装

## AUR 一键安装

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

## Deb 一键安装

```shell
curl -s https://assets.emqx.com/scripts/install-nanomq-deb.sh | sudo bash
sudo apt-get install nanomq
```

## Deb 手动安装

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

## Rpm 一键安装

```shell
curl -s https://assets.emqx.com/scripts/install-nanomq-rpm.sh | sudo bash
sudo yum install -y nanomq
```

## Rpm 手动安装

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
