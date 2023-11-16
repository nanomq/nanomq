# NFTP

`nftp` is a light-weight, no run time file transfer tool based on MQTT. `nftp` support P to P/ N to 1/ 1 to N transmission，asynchronous send / recv，discontinued transmission.

## Compile 

**Note**: nftp tool isn't built by default, you can enable it via `-DBUILD_NFTP=ON`.

```bash
$ mkdir build && cd build
$ cmake -G Ninja -DBUILD_NFTP=ON ..
$ Ninja
```

After the compilation, an executable file named `nanomq_cli` will be generated. Execute the following command to confirm that it can be used normally:

```bash
$ nanomq_cli
available tools:
   * pub
   * sub
   * conn
   * bench
   * nngproxy
   * nngcat
   * nftp

Copyright 2022 EMQ Edge Computing Team
```

```bash
$ nanomq_cli bench
Usage: nanomq_cli nftp { send | recv } [<opts>]
```

The output of the above content proves that `nftp` has been correctly compiled.

## Use

There are two subcommands of `bench`:

1. `send`: used to send files.
2. `recv`: Used to receive files.

Start `nftp recv` in the receive side and start `nftp send` in the send side. For specific usage, please refer to the following content.

## Parameter

When executing `nanomq_cli nftp --help`, you will get the available parameter output.

| Parameter         | abbreviation | Optional value | Default value     | Description                  |
| ----------------- | ------------ | -------------- | ----------------- | ---------------------------- |
| --url             | -            | -              | localhost         | address of MQTT broker       |
| --file            | -f           | -              | None; required    | path to the file             |
| --dir             | -d           | -              | current directory | directory to receive files   |

## Send

Execute `nanomq_cli nftp send --help` to get all available parameters of this subcommand. Their explanations have been included in the table above and are omitted here.

For example, we send file '/tmp/aaa/filename.c':

```bash
$ nanomq_cli nftp send --file /tmp/aaa/filename.c
```

## Recv

Execute `nanomq_cli nftp recv --help` to get all available parameters of this subcommand. Their explanations have been included in the table above and are omitted here.

For example, we start to recv, and save all files in directory '/tmp/':

```bash
$ nanomq_cli nftp recv -dir /tmp/
```

