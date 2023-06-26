#  安装

本节介绍了如何通过各种方法安装 NanoMQ，比如通过 Docker 安装 NanoMQ，通过安装包安装，或通过源码编译安装。

**[用Docker安装](http://localhost:8080/docs/en/latest/installation/docker.html)**

Docker用户会发现一个使用官方Docker镜像来安装和运行NanoMQ的指南。它还提供了为NanoMQ的使用配置Docker的说明，以及配置NanoMQ安装的环境变量的综合列表。

**[用软件包管理器安装](http://localhost:8080/docs/en/latest/installation/packages.html)**

NanoMQ目前提供以下安装包：

| 方法             | 描述                                                         |
| ---------------- | ------------------------------------------------------------ |
| AUR (Arch Linux) | 对于Arch Linux用户来说，NanoMQ可以使用AUR帮助器'yay'来安装。可以安装不同的版本，包括基本版、sqlite版、msquic版和完整版。 |
| DEB来源          | 基于Debian的Linux发行版如Ubuntu可以使用这种方法来安装NanoMQ。我们提供了一个脚本来简化安装过程。 |
| 手动DEB包        | 本节还提供了详细的步骤，将官方的emqx NanoMQ软件库添加到源列表中，并使用apt-get手动安装该软件。 |
| 转速来源         | 基于RHEL的Linux发行版如CentOS可以使用这种方法。提供了一个脚本来简化安装过程。 |
| 手动转速包       | 本节还提供了详细的步骤，将官方EMQX NanoMQ仓库添加到yum配置中，并使用yum手动安装该软件。 |

**[ 从源头建立](http://localhost:8080/docs/en/latest/installation/build-options.html)**

如果你想从源代码编译和安装NanoMQ，这部分还包括操作说明和可选的编译参数列表，以便进一步定制。