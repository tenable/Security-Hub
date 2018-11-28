# tenableio2securityhub
A python script for sending vulnerabilities from Tenable.io to AWS SecurityHub.

### Installation
```
pip install boto3 requests
```

### Python Version
3.7+

### Configuration
In order to use this script, you must first Subscribe to Tenable.io as a provider in AWS SecurityHub.

Once subscribed, update the following setting in the script with your [AWS Account ID](https://docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html#FindingYourAWSId):

    AWS_ACCOUNT_ID = '<YOUR_ACCOUNT_ID>'

Next, update the following setting with your [AWS Region](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RegionsAndAvailabilityZones.html):

    AWS_REGION = '<YOUR_AWS_REGION>'

Then, update the following settings with your [Tenable.io](https://cloud.tenable.com/) API keys:

    ACCESS_KEY = '<YOUR_ACCESS_KEY>'
    SECRET_KEY = '<YOUR_SECRET_KEY>'

### Run the script
Once configuration is complete, run the following command and--upon completion--you will see vulnerabilities from Tenable.io appear in your SecurityHub findings.

```
./python3 tenableio2securityhub.py
```
