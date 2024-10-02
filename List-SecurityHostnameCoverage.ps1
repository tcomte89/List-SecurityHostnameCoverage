#************************************************************************
#
# Name: List-SecurityHostnameCoverage
# Author: Thomas Comte
# Purpose: List the security coverages of hostnames where the delivery is in production
# Date: 18/09/2024
# Version: 2
#************************************************************************

# Parameters
Param(
    [Parameter()] [string] $OutputFile = ".\CoveragesStatus.json",
    [ValidateSet("CSV", "JSON", "Both")]
    [Parameter()] [string] $OutputFormat = "CSV", # Output format: CSV, JSON, Both (default is CSV)    
    [Parameter()] [string] $EdgeRCFile = "~\.edgerc",
    [Parameter()] [string] $Section = 'default',
    [Parameter()] [string] $AccountSwitchKey
)

# Import necessary modules if not already imported
if (!(Get-Module AkamaiPowershell)) {
    Import-Module AkamaiPowershell -DisableNameCheck
}
if (!(Get-Module DnsClient-PS)) {
    Install-Module DnsClient-PS -Scope CurrentUser -Force
    Import-Module DnsClient-PS
}

# Retrieve all properties
$AllProperties = List-AllProperties -EdgeRCFile $EdgeRCFile -Section $Section -AccountSwitchKey $AccountSwitchKey

# Prepare list of property names and versions
$ListPropertyNamesAndVersions = $AllProperties | Select propertyName, productionVersion | Where-Object { $_.productionVersion -ne $null }

# Initialize the results list
$FinalResultList = @()

# Security
# Run the List-AppSecConfigurations command and store the result
$Secconfigurations = Get-AppSecHostnameCoverage -EdgeRCFile $EdgeRCFile -Section $Section -AccountSwitchKey $AccountSwitchKey

# Process in parallel
$ListPropertyNamesAndVersions | ForEach-Object -Parallel {
    # Use $using: to access variables from the parent scope
    $PropertyNameandVersion = $_
    $EdgeRCFile = $using:EdgeRCFile
    $Section = $using:Section
    $AccountSwitchKey = $using:AccountSwitchKey
    $Secconfigurations = $using:Secconfigurations

    # Function to list property hostnames
    $PropertyHostnames = List-PropertyHostnames -PropertyName $PropertyNameandVersion.propertyName -PropertyVersion $PropertyNameandVersion.productionVersion -EdgeRCFile $EdgeRCFile -Section $Section -AccountSwitchKey $AccountSwitchKey
    
    $results = @()
    foreach ($PropertyHostname in $PropertyHostnames) {
        $ipaddress = ($(Resolve-Dns $PropertyHostname.cnameFrom -ErrorAction SilentlyContinue).Answers | Select -last 1).Address.IPAddressToString
 
        if ($ipaddress -eq $Null) {
          $CoveragesStatus = "NXDOMAINS"
        }
        elseif ($(((Resolve-Dns $ipaddress PTR).Answers | Select -last 1).PtrDomainName.Value | where {$_ -like "*akamai*"})){
          $CoveragesStatus = "$ipaddress, AKAMAI"
        # Adding control to handle IPs not belonging to Akamai but handled by Akamai
        }
        elseif ($((Resolve-Dns $PropertyHostname.cnameFrom).Answers | Select -first 1).CanonicalName.Value | where {($_ -like "*edgesuite*") -or ($_ -like "*edgekey*")}){
          $CoveragesStatus = "$ipaddress, AKAMAI"
        }
        else {
          $CoveragesStatus = "$ipaddress, OUT_OF_SCOPE"
        }


        # Initialize security configuration details
        $ConfigurationID = "null"
        $SecConfigurationName = "null"
        $SecConfigurationVersion = "null"
        $SechasMatchTarget = "False"
        $SecpolicyNames = "null"
        $Secstatus = "not_covered"

        # Check security configurations for the current hostname
        foreach ($Secconfiguration in $Secconfigurations) {
            if ($Secconfiguration.hostname -eq $PropertyHostname.cnameFrom) {
                $ConfigurationID = $Secconfiguration.configuration.id
                $SecConfigurationName = $Secconfiguration.configuration.name
                $SecConfigurationVersion = $Secconfiguration.configuration.version
                $SechasMatchTarget = $Secconfiguration.hasMatchTarget
                $SecpolicyNames = $Secconfiguration.policyNames -join ", "
                $Secstatus = $Secconfiguration.status
                break  # Exit the loop once a match is found
            }
        }

        # Determine Security Coverage
        if ($CoveragesStatus -match "OUT_OF_SCOPE|NXDOMAINS") {
            $SecurityCoverages = "UNPROTECTED"
        } elseif ($CoveragesStatus -match "AKAMAI" -and $SechasMatchTarget -eq $true) {
            $SecurityCoverages = "PROTECTED"
        } elseif ($CoveragesStatus -match "AKAMAI" -and $SechasMatchTarget -eq $false) {
            $SecurityCoverages = "UNPROTECTED"
        } else {
            $SecurityCoverages = "UNKNOWN"
        }

        # Creating the result object
        $result = [PSCustomObject]@{
            securityCoverages = $SecurityCoverages
            Hostname = $PropertyHostname.cnameFrom
            DNSStatus = $CoveragesStatus
            secStatus = $Secstatus
            securityName = $SecConfigurationName
            policyName = $SecpolicyNames
            propertyName = $PropertyNameandVersion.propertyName
            #productionVersion = $PropertyNameandVersion.productionVersion
            #edgeHostname = $PropertyHostname.cnameTo

        }
        $results += $result
    }
    $results
} -ThrottleLimit 5 | ForEach-Object {
    # Collect results outside of the parallel loop
    $FinalResultList += $_
}

# Output results

# Get the current date in YYYYMMDD format
$date = Get-Date -Format "yyyyMMdd"

# Sort the final result list by the securityCoverages property
$FinalResultList = $FinalResultList | Sort-Object -Property securityCoverages
# Format and output the sorted results
Write-Host "Date: " $date
$FinalResultList | Format-Table -AutoSize

# Handle output based on the selected format
switch ($OutputFormat) {
    "CSV" {
        $FinalResultList | Export-Csv -Path $date"-"$OutputFile".csv" -NoTypeInformation
        Write-Host "CSV output saved to:" $date"-"$OutputFile".csv"
    }
    "JSON" {
        $FinalResultList | ConvertTo-Json | Out-File -FilePath $date"-"$OutputFile".json"
        Write-Host "JSON output saved to:" $date"-"$OutputFile".json"
    }
    "Both" {
        # Export CSV
        $FinalResultList | Export-Csv -Path $date"-"$OutputFile".csv" -NoTypeInformation
        Write-Host "CSV output saved to:" $date"-"$OutputFile".csv"

        # Export JSON
        $FinalResultList | ConvertTo-Json | Out-File -FilePath $date"-"$OutputFile".json"
        Write-Host "JSON output saved to:" $date"-"$OutputFile".json"
    }
}

#-----

# Calculate counts and percentages
$TotalCount = $FinalResultList.Count
$ProtectedCount = ($FinalResultList | Where-Object { $_.SecurityCoverages -eq "PROTECTED" }).Count
$UnprotectedCount = ($FinalResultList | Where-Object { $_.SecurityCoverages -eq "UNPROTECTED" }).Count

$ProtectedPercentage = if ($TotalCount -ne 0) { [math]::Round(($ProtectedCount / $TotalCount) * 100, 2) } else { 0 }
$UnprotectedPercentage = if ($TotalCount -ne 0) { [math]::Round(($UnprotectedCount / $TotalCount) * 100, 2) } else { 0 }

# Output summary
Write-Host "Summary:"
Write-Host "Total Hostnames: $TotalCount"
Write-Host "PROTECTED Hostnames: $ProtectedCount ($ProtectedPercentage%)"
Write-Host "UNPROTECTED Hostnames: $UnprotectedCount ($UnprotectedPercentage%)"
