# Logs

Log in NanoMQ allows you to customize how the broker generates and manages log files. This configuration includes settings for the destination of the logs, the log levels, and the handling of log file rotation.

## **Example Configuration**

```hcl
log = {
  to = [file, console]                  # Destination of the logs
  level = "warn"                        # Log level
  dir = "/tmp"                          # Directory for log files
  file = "nanomq.log"                   # Filename for the log file
  rotation = {
    size = "10MB"                       # Maximum size of each log file
    count = 5                           # Maximum rotation count of log files
  }
}
```

## **Configuration Items**

- `to`: Specifies the destination(s) where the logs will be emitted. Optional values:
  - `file`: Write logs to a file.
  - `console`: Write logs to standard I/O
  - `syslog`: Write logs to syslog
- `level`: Specifies the log level. Only messages with a severity level equal to or higher than this level will be logged. Optional values:
  - `trace`
  - `debug`
  - `info`
  - `warn`
  - `error`
  - `fatal`
- `dir`: Specifies the directory where log files will be stored.
- `file`: Specifies the filename for the log file.
- `rotation`: Specifies the settings for log file rotation.
  - `size`: Specifies the maximum size of each log file. Once a log file reaches this size, it will be rotated. The value can be specified in KB, MB, or GB.
  - `count`: Specifies the maximum rotation count of log files. When the count limit is reached, the oldest log file will be deleted upon the next rotation.