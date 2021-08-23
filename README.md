# Script For Scanning IP Addresses or ELB Records Across Zebedee Accounts

This script will automatically fetch the EIP addresses and ELBs from an account to scan then print if the port(s) are accessible.  The idea is to run this script while not connect to the Zebedee VPN.

## How to use

You require an aws/config such as the following:

```
[default]
region = us-east-1
output = json
aws_access_key_id = ACCESS_KEY_ID
aws_secret_access_key = SECRET_KEY

[profile tools]
    role_arn = arn:aws:iam::SDFSDFDF:role/OrganizationAccountAccessRole
    source_profile = default


[profile dev]
    role_arn = arn:aws:iam::SDFSDFDF:role/OrganizationAccountAccessRole
    source_profile = default
```


The `profiles` are used as a parameter to determine a single environment to scan.  **The default is to scan all environments found in the AWS config**.

### ELB Scan

The script will fetch all ELBs in the corresponding account.  Classic ELBs are scan on the listener ports and ELBv2 is scanned on ports 80/443.

You can use the `--account` flag to scan specific accounts.

```
python3 scanranges.py --account dev --scan elb

OR 

python3 scanranges.py --account dev,tools --scan elb
```

Scan ELBs in all environments:

```

```



### IP Scan

The script will fetch the EIPs in the accounts and by default we scan ports `22,80,443,9735`.  You can use the `--ports` flag to scan other ports.

```
python3 scanranges.py --scan ip --account dev,tools


```

