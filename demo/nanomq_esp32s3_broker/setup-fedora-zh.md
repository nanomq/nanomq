# 在 Fedora 上使用 Zephyr 和 ESP\-IDF 编译 ESP32\-S3 完整指南

> **适用范围**：本指南面向 **Fedora**，是
> [demo/nanomq_esp32s3_broker](README.md) 的环境搭建参考。其他发行版步骤相同，
> 只需替换包管理器与包名（如 Debian/Ubuntu 的 `apt`）。文中出现的路径
> （如 `~/Projects/EMQ/ZephyrProject`）仅为示例，可自行选择。

以下是在 **Fedora** 环境下，结合 **VSCode \+ ESP\-IDF** 编译 Zephyr 到 **ESP32\-S3** 的完整详细指南。



本指南总结了开发过程中常见的环境冲突（如 Python 虚拟环境冲突、目录权限问题）以及 Zephyr 新版本（v4\.x/main 分支）工具链机制的变化，提供了一套最稳定、最省事的配置方案。



---

## 1\. 核心思路与架构



在开始之前，需要明确当前 Zephyr 环境配置的三个核心原则：

1. **复用 ESP\-IDF 的 Python 环境**：避免 Zephyr 和 ESP\-IDF 两个 Python 虚拟环境（venv）互相冲突，直接将 `west` 等工具安装到 ESP\-IDF 的 venv 中。

2. **使用 Zephyr SDK 作为编译器**：Zephyr 新版本（v4\.x 及 main 分支）已经移除了源码树内自带的 `espressif` 工具链 CMake 配置。编译 ESP32 系列必须依赖官方提供的 **Zephyr SDK**（其内部已包含 Espressif 专用的 Xtensa 工具链）。

3. **避免使用 ****`sudo`**：所有源码拉取、编译和构建操作必须在普通用户下进行，否则会导致严重的目录权限问题。

    

---



## 2\. 安装 Fedora 系统依赖



首先更新系统并安装 Zephyr 构建所需的基础依赖包：



```Bash
sudo dnf update -y
sudo dnf install -y \
    git cmake ninja-build gperf ccache dfu-util dtc wget file make \
    gcc gcc-c++ xz openssl-devel \
    python3-devel python3-pip python3-tkinter python3-wheel
```



**配置串口权限**（确保普通用户有权访问开发板串口）：

```Bash
sudo usermod -aG dialout $USER
```

> **注意**：执行完此命令后，**必须注销当前用户并重新登录**（或重启系统）才能生效。
> 
> 



---



## 3\. 准备 Python 环境与 Zephyr 源码



不要使用系统全局 Python，也不要单独创建 Zephyr 的 venv，直接复用你现有的 ESP\-IDF 环境。



### 3\.1 激活 ESP\-IDF 环境并安装 Zephyr 工具

假设你的 ESP\-IDF 激活脚本路径为 `~/.espressif/tools/activate_idf_v6.1.sh`（请根据实际版本调整）：



```Bash
# 激活 ESP-IDF 环境
source ~/.espressif/tools/activate_idf_v6.1.sh

# 升级 pip 并安装 west、esptool 和 pyserial
python -m pip install --upgrade pip
python -m pip install west esptool pyserial
```



### 3\.2 初始化 Zephyr 工作区

以普通用户身份拉取 Zephyr 源码（假设工作区放在 `~/Projects/EMQ/ZephyrProject`）：



```Bash
west init -m https://github.com/zephyrproject-rtos/zephyr ~/Projects/EMQ/ZephyrProject
cd ~/Projects/EMQ/ZephyrProject

# 更新所有 Zephyr 模块（耗时较长）
west update

# 导出 Zephyr CMake 包
west zephyr-export

# 安装 Zephyr 依赖的 Python 包
python -m pip install -r zephyr/scripts/requirements.txt

# 拉取 Espressif HAL blobs（必须执行一次）
west blobs fetch hal_espressif
```

> **务必执行 `west blobs fetch hal_espressif`。** 若跳过，`CONFIG_WIFI_ESP32` 会
> **静默变为不可见**：构建照常成功、固件照常启动，但没有 Wi-Fi 功能，且构建系统
> 不会给出任何警告——从 Kconfig 的角度看该选项并不存在。表现为串口上始终等不到
> `wifi: connected`。



---



## 4\. 安装 Zephyr SDK（关键步骤）



由于新版 Zephyr 不再内置 Espressif 工具链的 CMake 描述文件，必须安装 Zephyr SDK。SDK 内部已经包含了专为 ESP32 系列优化的 `xtensa-espressif_esp32s3_zephyr-elf` 工具链。



### 4\.1 下载并解压 SDK

```Bash
cd ~
wget https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v1.0.1/zephyr-sdk-1.0.1_linux-x86_64_gnu.tar.xz
tar xvf zephyr-sdk-1.0.1_linux-x86_64_gnu.tar.xz
```



### 4\.2 运行安装脚本并选择工具链

```Bash
cd ~/zephyr-sdk-1.0.1
./setup.sh
```

在弹出的交互式菜单中：

1. 选择安装目标架构：勾选 **`xtensa-espressif_esp32s3_zephyr-elf`**（如果还需要编译 ESP32\-C3/C6 等 RISC\-V 芯片，可一并勾选 `riscv64-zephyr-elf`）。

2. 按提示完成安装。

    

---



## 5\. 固化环境变量



为了避免每次打开新终端都需要手动配置，将环境变量写入 `~/.bashrc`。



```Bash
cat <<'EOF' >> ~/.bashrc

# =========================================================
# Zephyr + ESP32-S3 开发环境配置
# =========================================================
alias esp-zephyr='source ~/.espressif/tools/activate_idf_v6.1.sh && export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1 && unset ZEPHYR_TOOLCHAIN_VARIANT'
EOF
```



使配置生效：

```Bash
source ~/.bashrc
```



> **说明**：
> 
> - `source ...`：激活 ESP\-IDF 环境，提供 `esptool` 等烧录工具。
> 
> - `export ZEPHYR_SDK_INSTALL_DIR=...`：告诉 CMake 去哪里找 Zephyr SDK。
> 
> - `unset ZEPHYR_TOOLCHAIN_VARIANT`：**非常重要**。确保 Zephyr 使用默认的 SDK 寻找逻辑，而不是去寻找已被废弃的 `espressif` 变体。
> 
> 



---



## 6\. 编译与烧录流程



以后每次开发，只需按照以下步骤操作：



### 6\.1 激活环境

```Bash
esp-zephyr
```



### 6\.2 编译示例代码

进入 Zephyr 源码目录并编译 `hello_world`：

```Bash
cd ~/Projects/EMQ/ZephyrProject/zephyr

# 强制清理旧缓存并构建
west build -p always -b esp32s3_devkitc/esp32s3/procpu samples/hello_world
```

*注：新版 Zephyr 中 **`esp32s3_devkitm`* 已重命名为 `esp32s3_devkitc`*。*



### 6\.3 烧录固件

连接 ESP32\-S3 开发板，执行：

```Bash
west flash
```

如果提示找不到串口，可以手动指定：

```Bash
west flash -- --port /dev/ttyUSB0  # 或 /dev/ttyACM0
```



### 6\.4 查看串口日志

```Bash
python -m serial.tools.miniterm /dev/ttyUSB0 115200
```

*\(按 **`Ctrl + ]`** 退出 miniterm\)*



---



## 7\. 常见问题排查 \(Troubleshooting\)



### 问题 1：`Permission denied` 或文件属主为 `root`

**现象**：`west build` 报错 `PermissionError`，或者 `ls -l` 发现 Zephyr 源码目录属主是 `root`。

**原因**：之前误用了 `sudo west ...` 或 `sudo git ...`，或者从 Docker 容器拷贝了文件。

**解决**：

```Bash
# 将整个工作区属主改回当前用户
sudo chown -R "$(id -un):$(id -gn)" ~/Projects/EMQ/ZephyrProject

# 清理可能由 root 生成的 build 目录
sudo rm -rf ~/Projects/EMQ/ZephyrProject/zephyr/build
```

**切记**：永远不要对 `west`、`git`、`cmake` 使用 `sudo`。



### 问题 2：`Could not find a package configuration file provided by "Zephyr-sdk"`

**现象**：CMake 报错找不到 Zephyr SDK。

**原因**：未安装 Zephyr SDK，或未正确设置 `ZEPHYR_SDK_INSTALL_DIR`。

**解决**：

确保执行了 `esp-zephyr` 别名，并且该别名中正确导出了 `ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1`。



### 问题 3：`include could not find requested file: .../cmake/toolchain/espressif/generic.cmake`

**现象**：CMake 报错找不到 espressif 工具链配置文件。

**原因**：环境变量中残留了旧版的 `ZEPHYR_TOOLCHAIN_VARIANT=espressif`，导致 CMake 去源码树里找已被移除的文件。

**解决**：

```Bash
unset ZEPHYR_TOOLCHAIN_VARIANT
rm -rf ~/Projects/EMQ/ZephyrProject/zephyr/build
```

确保你的 `~/.bashrc` 中的 `esp-zephyr` 别名包含 `unset ZEPHYR_TOOLCHAIN_VARIANT`。



### 问题 4：CMake 缓存指向旧路径 \(如 `/workdir`\)

**现象**：报错提示路径包含 `/workdir` 或其他不存在的目录。

**原因**：旧的 `build` 目录或 `.west/config` 缓存了错误的路径。

**解决**：

```Bash
cd ~/Projects/EMQ/ZephyrProject/zephyr
rm -rf build
unset ZEPHYR_BASE
west config zephyr.base --delete || true
west build -p always -b esp32s3_devkitc/esp32s3/procpu samples/hello_world
```



