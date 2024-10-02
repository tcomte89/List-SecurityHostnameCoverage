# Features
- Retrieves all properties and their hostnames in production.
- Checks DNS coverage for each hostname.
- Matches hostnames with Akamai security configurations to determine coverage status.
- Provides a summary of the number and percentage of PROTECTED and UNPROTECTED hostnames.

# Parameters
The script accepts the following parameters:
- '**OutputFile**' (string): Path where the results will be saved in CSV format default. Default is .\CoveragesStatus.json.
- '**OutputFormat**' (string): Export the results in either CSV, JSON, or both formats. Default is CSV.
- '**EdgeRCFile**' (string): Path to the Akamai EdgeRC file. Default is ~\.edgerc.
- '**Section**' (string): The section within the EdgeRC file. Default is 'default'.
- '**AccountSwitchKey**' (string): Optional key for account switching.

# Installation
1. Install Required Modules: Ensure the required PowerShell modules are installed. The script checks and installs them if needed:
- AkamaiPowershell: For interacting with Akamai services.
- DnsClient-PS: For DNS resolution.
```bash
if (!(Get-Module AkamaiPowershell)) {
    Import-Module AkamaiPowershell -DisableNameCheck
}
if (!(Get-Module DnsClient-PS)) {
    Install-Module DnsClient-PS -Scope CurrentUser -Force
    Import-Module DnsClient-PS
}

```

# General Use
To run the script and retrieve security coverages:
.\List-SecurityHostnameCoverage.ps1 -OutputFile "result" -OutputFormat "Both" -Section "default"

Result: 
```bash
20240918-result.csv
20240918-result.csv
```

# Functionality
1. Retrieve All Properties: Fetches all properties and their versions from Akamai.
1. Prepare Hostnames: Retrieves and processes property hostnames.
1. Check DNS Coverage: Determines DNS status and whether it’s covered by Akamai.
1. Match Security Configurations: Matches hostnames with security configurations and determines the security coverage.
1. Output Results: Saves the results to either a CSV, JSON, or BOTH file format and displays a formatted table.
1. Summary: Provides a summary of PROTECTED and UNPROTECTED hostnames with counts and percentages.

# Output
The script generates the following outputs:
- CSV/JSON File: Contains detailed results of security coverage for each hostname, with the date of the check included in the file name.
- Formatted Table: Displays results in a readable table format.
- Summary: Outputs a summary of PROTECTED and UNPROTECTED hostnames including counts and percentages.

**Example**
Here’s an example of how the output might look:

```json
[
    {
        "securityCoverages": "PROTECTED",
        "Hostname": "test.example.com",
        "DNSStatus": "1.2.3.4, AKAMAI",
        "secStatus": "covered",
        "securityName": "WAF Security File",
        "policyName": "policyname",
        "propertyName": "example-property"
    },
    ...
]
```

**Formatted Table**

```bash
| securityCoverages | Hostname         | DNSStatus          | secStatus | securityName       | policyName | propertyName      |
|-------------------|------------------|---------------------|-----------|--------------------|------------|-------------------|
| PROTECTED         | test.example.com | 192.0.2.1, AKAMAI  | covered   | WAF Security File  | policyname | example-property  |
| UNPROTECTED       | example.com      | 192.0.2.2, OUT_OF_SCOPE | uncovered | n/a                | n/a        | example-property  |
```

```bash
CSV output saved to: 20240918-result.csv 
```

**Summary**
```bash
Summary:
Total Hostnames: 100
PROTECTED Hostnames: 30 (30.00%)
UNPROTECTED Hostnames: 70 (70.00%)
```
