# Tenable Vulnerability Management to AWS Transformer

This tool is designed to consume Tenable.io asset and vulnerability data,
transform that data into the AWS Security Hub Finding format, and then upload
the resulting data into AWS Security Hub.

The tool can be run as either a one-shot docker container or as a command-line
tool. To run as a docker image, you'll need to build the image and then pass
the config file to the container.

## Requirements

- The Tenable Vulnerability Management Integration for Security Hub must be
  configured to accept findings from the integration.
- At a minimum the configuration file must have the account id that the events
  will be sent to.  Ideally the region should be configured as well.
- A set of API Keys within TVM should be configured to allow exportation of
  assets and vulnerability findings from the platform.  These keys should be
  wither configured within the configuration file or as environment variables

## Installation

```
pip install tvm2aws
```

## Configuration

Simply build a configuration file (or use the [example file][cfg] provided)
with the following details:

```toml
aws_account_id = 12344567890
aws_region = "us-east-1"
access_key = "1234567890abcdef1234567890"
secret_key = "1234567890abcdef1234567890"
```

## Running the integration

```
❯ tvm2aws --configfile /path/to/config.toml
```


## Commandline options

```
❯ tvm2aws --help

 Usage: tvm2aws [OPTIONS]

 Tenable to AWS Security Hub vulnerability finding importer.

╭─ Options ───────────────────────────────────────────────────────────────────╮
│ --configfile          PATH                  [default: tvm2aws.toml]         │
│ --verbose     -v      INTEGER RANGE [x<=5]  [default: 2]                    │
│ --help                                      Show this message and exit.     │
╰─────────────────────────────────────────────────────────────────────────────╯
```

[cfg]: tvm2aws.toml
