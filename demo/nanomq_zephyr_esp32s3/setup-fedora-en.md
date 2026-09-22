# Complete Guide to Building ESP32-S3 with Zephyr and ESP-IDF on Fedora

> **Scope**: This guide targets **Fedora** and is an environment setup
> reference for [demo/nanomq_zephyr_esp32s3](README.md). The steps are the
> same on other distributions; replace the package manager and package names
> as needed (for example, use `apt` on Debian/Ubuntu). Paths such as
> `~/Projects/EMQ/ZephyrProject` are examples and can be changed.

This is a complete guide to building Zephyr for **ESP32-S3** on **Fedora**
with **VS Code + ESP-IDF**.

It also covers common development environment issues, such as Python virtual
environment conflicts and directory permission problems, as well as the
toolchain changes introduced in newer Zephyr versions (v4.x / main branch).
It provides a stable and low-maintenance setup workflow.

---

## 1. Core approach and architecture

Before starting, keep these three principles in mind:

1. **Reuse the ESP-IDF Python environment**: Avoid conflicts between separate
   Zephyr and ESP-IDF Python virtual environments (venvs) by installing tools
   such as `west` in the ESP-IDF venv.

2. **Use the Zephyr SDK toolchain**: Newer Zephyr versions (v4.x and the
   main branch) have removed the `espressif` toolchain CMake configuration
   from the source tree. Building ESP32 targets requires the official
   **Zephyr SDK**, which includes the Espressif-specific Xtensa toolchain.

3. **Avoid using `sudo`**: Fetch source code and perform all build operations
   as a regular user. Using `sudo` may cause serious directory ownership
   issues.

---

## 2. Install Fedora system dependencies

Update the system and install the basic dependencies required by Zephyr:

```Bash
sudo dnf update -y
sudo dnf install -y \
    git cmake ninja-build gperf ccache dfu-util dtc wget file make \
    gcc gcc-c++ xz openssl-devel \
    python3-devel python3-pip python3-tkinter python3-wheel
```

**Configure serial-port permissions** so the regular user can access the
development board:

```Bash
sudo usermod -aG dialout $USER
```

> **Note**: You **must log out and log back in** (or reboot) after running
> this command for the change to take effect.

---

## 3. Prepare the Python environment and Zephyr source

Do not use the system Python installation or create a separate Zephyr venv.
Reuse your existing ESP-IDF environment instead.

### 3.1 Activate ESP-IDF and install Zephyr tools

Assume the ESP-IDF activation script is
`~/.espressif/tools/activate_idf_v6.1.sh`; adjust the path for your version:

```Bash
# Activate the ESP-IDF environment
source ~/.espressif/tools/activate_idf_v6.1.sh

# Upgrade pip and install west, esptool, and pyserial
python -m pip install --upgrade pip
python -m pip install west esptool pyserial
```

### 3.2 Initialize the Zephyr workspace

Fetch Zephyr source as a regular user. This example places the workspace at
`~/Projects/EMQ/ZephyrProject`:

```Bash
west init -m https://github.com/zephyrproject-rtos/zephyr ~/Projects/EMQ/ZephyrProject
cd ~/Projects/EMQ/ZephyrProject

# Update all Zephyr modules (this may take a while)
west update

# Export the Zephyr CMake package
west zephyr-export

# Install Python packages required by Zephyr
python -m pip install -r zephyr/scripts/requirements.txt

# Fetch Espressif HAL blobs (required once)
west blobs fetch hal_espressif
```

> **Be sure to run `west blobs fetch hal_espressif`.** If this step is
> skipped, `CONFIG_WIFI_ESP32` becomes **silently unavailable**: the build
> succeeds and the firmware boots, but Wi-Fi is absent, and the build system
> gives no warning because the option does not exist from Kconfig's
> perspective. The symptom is that the serial log never reaches
> `wifi: connected`.

---

## 4. Install Zephyr SDK (critical step)

Because newer Zephyr versions no longer include the Espressif toolchain CMake
configuration, the Zephyr SDK is required. The SDK includes the
`xtensa-espressif_esp32s3_zephyr-elf` toolchain optimized for ESP32 targets.

### 4.1 Download and extract the SDK

```Bash
cd ~
wget https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v1.0.1/zephyr-sdk-1.0.1_linux-x86_64_gnu.tar.xz
tar xvf zephyr-sdk-1.0.1_linux-x86_64_gnu.tar.xz
```

### 4.2 Run the setup script and select the toolchain

```Bash
cd ~/zephyr-sdk-1.0.1
./setup.sh
```

In the interactive menu:

1. Select **`xtensa-espressif_esp32s3_zephyr-elf`** as an installation
   target. If you also need to build for RISC-V chips such as ESP32-C3/C6,
   select `riscv64-zephyr-elf` as well.
2. Follow the prompts to complete the installation.

---

## 5. Persist the environment variables

To avoid configuring the environment manually in every new terminal, append
the following configuration to `~/.bashrc`:

```Bash
cat <<'EOF' >> ~/.bashrc

# =========================================================
# Zephyr + ESP32-S3 development environment
# =========================================================
alias esp-zephyr='source ~/.espressif/tools/activate_idf_v6.1.sh && export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1 && unset ZEPHYR_TOOLCHAIN_VARIANT'
EOF
```

Apply the configuration:

```Bash
source ~/.bashrc
```

> **Explanation**:
>
> - `source ...` activates ESP-IDF and provides tools such as `esptool` for
>   flashing.
> - `export ZEPHYR_SDK_INSTALL_DIR=...` tells CMake where to find Zephyr SDK.
> - `unset ZEPHYR_TOOLCHAIN_VARIANT` is **very important**. It ensures that
>   Zephyr uses the default SDK discovery logic instead of looking for the
>   removed `espressif` variant.

---

## 6. Build and flash workflow

For subsequent development, use the following steps.

### 6.1 Activate the environment

```Bash
esp-zephyr
```

### 6.2 Build the example

Enter the Zephyr source directory and build `hello_world`:

```Bash
cd ~/Projects/EMQ/ZephyrProject/zephyr

# Force a clean rebuild
west build -p always -b esp32s3_devkitc/esp32s3/procpu samples/hello_world
```

*Note: In newer Zephyr versions, **`esp32s3_devkitm`** was renamed to
**`esp32s3_devkitc`**.*

### 6.3 Flash the firmware

Connect the ESP32-S3 development board and run:

```Bash
west flash
```

If the serial port cannot be found, specify it manually:

```Bash
west flash --runner esp32 --esp-device /dev/ttyUSB0  # or /dev/ttyACM0
```

### 6.4 View the serial log

```Bash
python -m serial.tools.miniterm /dev/ttyUSB0 115200
```

*Press **`Ctrl + ]`** to exit miniterm.*

---

## 7. Troubleshooting

### Problem 1: `Permission denied` or files owned by `root`

**Symptoms**: `west build` reports `PermissionError`, or `ls -l` shows that
the Zephyr source directory is owned by `root`.

**Cause**: `sudo west ...` or `sudo git ...` was used accidentally, or files
were copied from a Docker container.

**Solution**:

```Bash
# Change ownership of the entire workspace back to the current user
sudo chown -R "$(id -un):$(id -gn)" ~/Projects/EMQ/ZephyrProject

# Remove a build directory that may have been created by root
sudo rm -rf ~/Projects/EMQ/ZephyrProject/zephyr/build
```

**Remember**: Never use `sudo` with `west`, `git`, or `cmake`.

### Problem 2: `Could not find a package configuration file provided by "Zephyr-sdk"`

**Symptoms**: CMake cannot find Zephyr SDK.

**Cause**: Zephyr SDK is not installed, or `ZEPHYR_SDK_INSTALL_DIR` is
incorrect.

**Solution**: Make sure you ran the `esp-zephyr` alias and that it exports
`ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1`.

### Problem 3: `include could not find requested file: .../cmake/toolchain/espressif/generic.cmake`

**Symptoms**: CMake cannot find the Espressif toolchain configuration file.

**Cause**: The old `ZEPHYR_TOOLCHAIN_VARIANT=espressif` remains in the
environment, causing CMake to look for a file removed from the source tree.

**Solution**:

```Bash
unset ZEPHYR_TOOLCHAIN_VARIANT
rm -rf ~/Projects/EMQ/ZephyrProject/zephyr/build
```

Make sure the `esp-zephyr` alias in `~/.bashrc` contains
`unset ZEPHYR_TOOLCHAIN_VARIANT`.

### Problem 4: CMake cache points to an old path (such as `/workdir`)

**Symptoms**: An error mentions `/workdir` or another nonexistent directory.

**Cause**: An old `build` directory or `.west/config` contains an invalid
cached path.

**Solution**:

```Bash
cd ~/Projects/EMQ/ZephyrProject/zephyr
rm -rf build
unset ZEPHYR_BASE
west config zephyr.base --delete || true
west build -p always -b esp32s3_devkitc/esp32s3/procpu samples/hello_world
```
