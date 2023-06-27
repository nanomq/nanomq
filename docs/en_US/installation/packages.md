# Install from packagecloud source

## Install via AUR

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

## Install via deb source

```shell
curl -s https://assets.emqx.com/scripts/install-nanomq-deb.sh | sudo bash
sudo apt-get install nanomq
```

## Install deb package manually

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



## Install via rpm source

```shell
curl -s https://assets.emqx.com/scripts/install-nanomq-rpm.sh | sudo bash
sudo yum install -y nanomq
```

## Install rpm package manually

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
