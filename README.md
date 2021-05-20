# PV204_Noise_Protocol_and_TPM


Link to the [assignment](https://is.muni.cz/auth/el/fi/jaro2021/PV204/um/lectures/pv204_project_overview_2021.pdf).



## Setup

Requires go 1.16 or newer.

```sh
cd client
go get .
cd ../server
go get .
cd ..
```

## Quickstart

Server and client need to run simultaniously and be able to comunicate.

#### Server quickstart

The registration string will be uniquely generated based on your environment and keys that get generated.

```bash
$ pv204-noise-protocol-and-TPM/server$ go run .
Server registration string: O/+BAwEBEVNlcnZlckluZm9ybWF0aW9uAf+CAAECAQhMb2NhdGlvbgEMAAEJUHVibGljS2V5Af+EAAAAGf+DAQEBCVszMl11aW50OAH/hAABBgFAAABG/4IBDjEyNy4wLjAuMTo2NjY2ASAl/87/r37/uTX/kf/Z//z/qgAZ/8b/y2f/21L/mP+k/8YkaHZOV//Nef+u/8BD/6gJAA==
```

#### Client quickstart

Securely communicate the registration string from server to client.

```bash
# Registration
pv204-noise-protocol-and-TPM/client$ go run . registration --server-string "INSERT REGISTRATION STRING THAT YOU HAVE FROM SERVER" --username "YOUR USERNAME" --keyfile "keyfile.bin"

# Send msg
pv204-noise-protocol-and-TPM/client$ go run . login --keyfile "keyfile.bin" --send-msg "lorem ipsum"

# Receive msgs
pv204-noise-protocol-and-TPM/client$ go run . login --keyfile "keyfile.bin" --receive-msg

# Interactive mode
pv204-noise-protocol-and-TPM/client$ go run . login --keyfile "keyfile.bin" --period 6

# Select correct TPM (if for some reason you have multiple) - Linux only
pv204-noise-protocol-and-TPM/client$ go run . login --keyfile "keyfile.bin" --tpm-path /dev/tpm0
# or for kernel-managed access
pv204-noise-protocol-and-TPM/client$ go run . login --keyfile "keyfile.bin" --tpm-path /dev/tpmrm0

```

## Client CLI help

The argument tpm-path is not used for Windows app. For Linux app it has default `/dev/tpm0`.

> TPM 2.0 allows direct access via /dev/tpm0 (one client at a time), managed access through the tpm2-abrmd resource manager daemon, or kernel-managed access via /dev/tpmrm0.    - Excerpt from [Arch wiki](https://wiki.archlinux.org/index.php/Trusted_Platform_Module)

#### Client CLI generic help

```bash
pv204-noise-protocol-and-TPM/client$ go run . -h
NAME:
   PV204 Noise TPM chat client - A new cli application

USAGE:
   client.exe [global options] command [command options] [arguments...]

VERSION:
   v0.0.1

COMMANDS:
   registration  Perform a registration
   login         Login and do some action. If send-msg or receive-msg are specified the action(s) will be performed and exited. If they are not specified, interactive interface will be launched.
   help, h       Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help (default: false)
   --version, -v  print the version (default: false)
```

#### Client CLI registration help

```bash
pv204-noise-protocol-and-TPM/client$ go run . registration -h
NAME:
   client.exe registration - Perform a registration

USAGE:
   client.exe registration [command options] [arguments...]

OPTIONS:
   --server-string value, -s value
   --username value, -u value
   --keyfile value, -k value        (default: "keypair.bin")
   --tpm-path value, -t value       (default: "IGNORED_ON_WINDOWS")
   --help, -h                       show help (default: false)
```

#### Client CLI login help

```bash
pv204-noise-protocol-and-TPM/client$ go run . login -h
NAME:
   client.exe login - Login and do some action. If send-msg or receive-msg are specified the action(s) will be performed and exited. If they are not specified, interactive interface will be launched.

USAGE:
   client.exe login [command options] [arguments...]

OPTIONS:
   --period value, -p value    Value is in seconds (default: 5)
   --keyfile value, -k value   (default: "keypair.bin")
   --tpm-path value, -t value  (default: "IGNORED_ON_WINDOWS")
   --send-msg value, -m value  Non-interactive mode: A single msg to be sent.
   --receive-msg, -r           Non-interactive mode: Using this flag you can retrieve msgs once. (default: false)
   --help, -h                  show help (default: false)
```

