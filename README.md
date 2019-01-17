# Tenable.io -> AWS Security Hub Transformer

This tool is designed to consume Tenable.io asset and vulnerability data,
transform that data into the AWS Security Hub Finding format, and then upload
the resulting data into AWS Security Hub.

The tool can be run as either a one-shot docker container or as a command-line
tool.  To run as a docker image, you'll need to build the image and then pass
the necessary secrets on to the container.

To run as a command-line tool, you'd need to install the required python modules
and then can run the tool using either environment variables or by passing the
required parameters as run-time parameters.

### Building for Docker

```shell
docker build -t tio2sechub:latest .
```

### Installing Python Requirements
```shell
pip install -r requirements.txt
```

### Configuration
The following below details both the command-line arguments as well as the 
equivalent environment variables.

```
usage: sechubingest.py [-h] [--tio-access-key TIO_ACCESS_KEY]
                       [--tio-secret-key TIO_SECRET_KEY]
                       [--batch-size BATCH_SIZE] [--aws-region AWS_REGION]
                       [--aws-account-id AWS_ACCOUNT_ID]
                       [--aws-access-id AWS_ACCESS_ID]
                       [--aws-secret-key AWS_SECRET_KEY]
                       [--log-level LOG_LEVEL] [--since OBSERVED_SINCE]

optional arguments:
  -h, --help            show this help message and exit
  --tio-access-key TIO_ACCESS_KEY
                        Tenable.io Access Key
  --tio-secret-key TIO_SECRET_KEY
                        Tenable.io Secret Key
  --batch-size BATCH_SIZE
                        Size of the batches to populate into Security Hub
  --aws-region AWS_REGION
                        AWS region for Security Hub
  --aws-account-id AWS_ACCOUNT_ID
                        AWS Account ID
  --aws-access-id AWS_ACCESS_ID
                        AWS Access ID
  --aws-secret-key AWS_SECRET_KEY
                        AWS Secret Key
  --log-level LOG_LEVEL
                        Log level: available levels are debug, info, warn,
                        error, crit
  --since OBSERVED_SINCE
                        The unix timestamp of the age threshold
```