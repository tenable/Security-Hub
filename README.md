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

### Requirements:

* Tenable.io's AWS Connector must be configured to pull the relavent metadata into Tenable.io.
* AWS Accound id, Access id, and Secret Key
* AWS Region to import the data into
* Tenable.io API Keys for an Admin-level user (required for exports)
* A host to run the integration on.  As this integration is cloud-to-cloud, the only stipulation is that it must be able to reach out to both cloud platforms.


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
                       [--batch-size BATCH_SIZE] 
                       [--aws-region AWS_REGION]
                       [--aws-account-id AWS_ACCOUNT_ID]
                       [--aws-access-id AWS_ACCESS_ID]
                       [--aws-secret-key AWS_SECRET_KEY]
                       [--log-level LOG_LEVEL] 
                       [--since OBSERVED_SINCE]
                       [--severities SEVERITIES]
                       [--run-every RUN_EVERY]

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
  --severities
                        What Severities should be ingested? Colon delimited
  --since OBSERVED_SINCE
                        The unix timestamp of the age threshold
  --run-every RUN_EVERY
                        How many hours between recurring imports
```

### Usage

Run the import once:

```
./sechubingest.py                       \
    --tio-access-key {TIO_ACCESS_KEY}   \
    --tio-secret-key {TIO_SECRET_KEY}   \
    --aws-region us-east-1              \
    --aws-account-id {AWS_ACCOUNT_ID}   \
    --aws-access-id {AWS_ACCESS_ID}     \
    --aws-secret-key {AWS_SECRET_KEY}   \
```

Run the import once an hour:

```
./sechubingest.py                       \
    --tio-access-key {TIO_ACCESS_KEY}   \
    --tio-secret-key {TIO_SECRET_KEY}   \
    --aws-region us-east-1              \
    --aws-account-id {AWS_ACCOUNT_ID}   \
    --aws-access-id {AWS_ACCESS_ID}     \
    --aws-secret-key {AWS_SECRET_KEY}   \
    --run-every 1
```

Run the same import using environment vars:

```
export TIO_ACCESS_KEY="{TIO_ACCESS_KEY}"
export TIO_SECRET_KEY="{TIO_SECRET_KEY}"
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID="{AWS_ACCOUNT_ID}"
export AWS_ACCESS_ID="{AWS_ACCESS_ID}"
export AWS_SECRET_KEY="{AWS_SECRET_KEY}"
export RUN_EVERY=1
./sechubingest.py
```

### Changelog
[Visit the CHANGELOG](https://github.com/tenable/Security-Hub/blob/master/CHANGELOG.md)
