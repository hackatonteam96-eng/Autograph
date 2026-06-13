#Requires -Version 5.1
<#
.SYNOPSIS
  AuthGraph ITDR — collect AD posture + recent security events (run on DC).
.DESCRIPTION
  Outputs one JSON file matching CrowdStrike-style Inventory & Posture findings.
  Run as Domain Admin on the DC. No external modules required.
.EXAMPLE
  .\Collect-LabSnapshot.ps1 -OutputPath C:\AuthGraph\out\dc-snapshot.json
#>
param(
    [string]$OutputPath = "C:\AuthGraph\out\dc-snapshot.json",
    [string]$ClientHostname = "",
    [int]$SecurityEventHours = 24,
    [int]$SecurityEventLimit = 200
)

$ErrorActionPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath) | Out-Null

function New-Finding {
    param([string]$Title, [string]$Severity, [string]$Category, [string]$Detail, [string]$Host = "DC")
    [PSCustomObject]@{
        title    = $Title
        severity = $Severity
        category = $Category
        host     = $Host
        detail   = $Detail
    }
}

$findings = @()
$hostName = $env:COMPUTERNAME
$domain   = (Get-CimInstance Win32_ComputerSystem).Domain

# --- Posture checks (screenshot items) ---

# Password policy
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $policy = Get-ADDefaultDomainPasswordPolicy
    if ($policy.MinPasswordLength -lt 12 -or -not $policy.ComplexityEnabled) {
        $findings += New-Finding "Inadequate Password Policy" "medium" "posture" `
            "MinLength=$($policy.MinPasswordLength), Complexity=$($policy.ComplexityEnabled)"
    }
} catch {
    $findings += New-Finding "Inadequate Password Policy" "medium" "posture" "Could not read AD password policy (RSAT/AD module?)"
}

# SMB signing (registry)
$smbServer = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction SilentlyContinue
if ($smbServer -and $smbServer.RequireSecuritySignature -ne 1) {
    $findings += New-Finding "SMB Signing Disabled" "medium" "posture" "RequireSecuritySignature is not enforced on $hostName"
}

# LDAP signing
$ldapPolicy = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
$ldapSigning = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
if (-not $ldapSigning -or $ldapSigning.LDAPServerIntegrity -ne 2) {
    $findings += New-Finding "LDAP Signing is not Required" "medium" "posture" "LDAPServerIntegrity not set to 2 (require signing) on DC"
}

# LDAPS channel binding (simplified lab check)
$channelBinding = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
if (-not $channelBinding -or $channelBinding.LdapEnforceChannelBinding -lt 2) {
    $findings += New-Finding "LDAPS Channel Binding is not Required" "medium" "posture" "LdapEnforceChannelBinding < 2 on DC"
}

# Print Spooler on DC
$spooler = Get-Service Spooler -ErrorAction SilentlyContinue
if ($spooler -and $spooler.Status -eq "Running") {
    $findings += New-Finding "Print Spooler Service Running" "medium" "posture" "Spooler running on domain controller $hostName"
}

# KRBTGT password age
try {
    $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet -ErrorAction Stop
    $days = ((Get-Date) - $krbtgt.PasswordLastSet).Days
    if ($days -gt 180) {
        $findings += New-Finding "KRBTGT password not changed for 180 days" "low" "posture" "krbtgt PasswordLastSet is $days days ago"
    }
} catch { }

# Attack path to privileged account (lab: users in Domain Admins or with SPN + sensitive groups)
try {
    $privileged = Get-ADGroupMember "Domain Admins" -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
    $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName |
        Select-Object -ExpandProperty SamAccountName
    $overlap = $spnUsers | Where-Object { $_ -in $privileged }
    if ($overlap) {
        $findings += New-Finding "Attack Path to a Privileged Account" "medium" "risk" "Service accounts with SPN also in privileged path: $($overlap -join ', ')"
    } else {
        # Lab demo path: any user with SPN linked to admin group membership chain
        foreach ($u in $spnUsers) {
            $groups = (Get-ADPrincipalGroupMembership $u -ErrorAction SilentlyContinue).Name
            if ($groups -match "Admin|SQL") {
                $findings += New-Finding "Attack Path to a Privileged Account" "medium" "risk" "Account $u has SPN and membership: $($groups -join ', ')"
                break
            }
        }
    }
} catch { }

# Stealthy privileges (GenericAll / DCSync-style — simplified)
try {
    $acl = Get-Acl "AD:\$((Get-ADDomain).DistinguishedName)"
    $findings += New-Finding "Stealthy Privileges" "low" "posture" "Review domain ACL for non-default delegated rights (manual follow-up in lab)"
} catch { }

# Privileged endpoint: Domain Admins logged on client (if client name provided)
if ($ClientHostname) {
    $start = (Get-Date).AddHours(-$SecurityEventHours)
    $daLogons = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4624
        StartTime = $start
    } -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object {
            $xml = [xml]$_.ToXml()
            $workstation = ($xml.Event.EventData.Data | Where-Object Name -eq "WorkstationName").'#text'
            $user = ($xml.Event.EventData.Data | Where-Object Name -eq "TargetUserName").'#text'
            $workstation -match $ClientHostname -and $user -match "Admin"
        }
    if ($daLogons) {
        $findings += New-Finding "Privileged Endpoint Account" "low" "risk" "Privileged-style logon detected toward client $ClientHostname"
    }
}

# Demo: compromised password flag if env var set (hackathon demo without HIBP)
if ($env:AUTHGRAPH_DEMO_COMPROMISED_USER) {
    $findings += New-Finding "Compromised Password" "high" "risk" "Demo flag: user $env:AUTHGRAPH_DEMO_COMPROMISED_USER marked compromised"
}

# --- Security events (4769 Kerberoasting, 4624, 4688 sample) ---
$since = (Get-Date).AddHours(-$SecurityEventHours)
$eventIds = 4769, 4624, 4688, 4662, 5136
$securityEvents = @()

foreach ($eid in $eventIds) {
    Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = $eid; StartTime = $since } `
        -MaxEvents ([math]::Floor($SecurityEventLimit / $eventIds.Count)) -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) { $data[$d.Name] = $d.'#text' }
            }
            $securityEvents += [PSCustomObject]@{
                time      = $_.TimeCreated.ToUniversalTime().ToString("o")
                event_id  = $eid
                host      = $hostName
                host_role = "dc"
                data      = $data
            }
        }
}

# DNS log tail (if DNS server role present)
$dnsEvents = @()
$dnsLog = "$env:SystemRoot\System32\dns\dns.log"
if (Test-Path $dnsLog) {
    Get-Content $dnsLog -Tail 50 -ErrorAction SilentlyContinue | ForEach-Object {
        $dnsEvents += @{ raw = $_; host = $hostName; host_role = "dc" }
    }
}

$snapshot = [PSCustomObject]@{
    collected_at = (Get-Date).ToUniversalTime().ToString("o")
    source       = "powershell"
    host         = $hostName
    host_role    = "dc"
    domain       = $domain
    findings     = $findings
    security_events = $securityEvents
    dns_events   = $dnsEvents
    http_events  = @()   # no IIS on typical DC; client script can fill
}

$snapshot | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Snapshot written: $OutputPath ($($findings.Count) findings, $($securityEvents.Count) security events)"
