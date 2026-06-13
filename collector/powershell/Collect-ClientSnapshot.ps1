#Requires -Version 5.1
<#
.SYNOPSIS
  AuthGraph ITDR — collect client security + optional IIS HTTP log tail.
.EXAMPLE
  .\Collect-ClientSnapshot.ps1 -OutputPath C:\AuthGraph\out\client-snapshot.json
#>
param(
    [string]$OutputPath = "C:\AuthGraph\out\client-snapshot.json",
    [int]$SecurityEventHours = 24,
    [int]$SecurityEventLimit = 100
)

$ErrorActionPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath) | Out-Null

$hostName = $env:COMPUTERNAME
$since = (Get-Date).AddHours(-$SecurityEventHours)
$eventIds = 4624, 4688, 4104
$securityEvents = @()

foreach ($eid in $eventIds) {
    $logName = if ($eid -eq 4104) { "Microsoft-Windows-PowerShell/Operational" } else { "Security" }
    Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = $eid; StartTime = $since } `
        -MaxEvents ([math]::Floor($SecurityEventLimit / $eventIds.Count)) -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) { $data[$d.Name] = $d.'#text' }
            }
            $securityEvents += @{
                time      = $_.TimeCreated.ToUniversalTime().ToString("o")
                event_id  = $eid
                host      = $hostName
                host_role = "client"
                data      = $data
            }
        }
}

$httpEvents = @()
$iisLogDir = "$env:SystemRoot\System32\LogFiles\HTTPERR"
if (Test-Path $iisLogDir) {
    Get-ChildItem $iisLogDir -Filter "*.log" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 |
        ForEach-Object { Get-Content $_.FullName -Tail 30 | ForEach-Object { $httpEvents += @{ raw = $_; host = $hostName } } }
}

$dnsEvents = @()
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -MaxEvents 30 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $dnsEvents += @{
            time = $_.TimeCreated.ToUniversalTime().ToString("o")
            message = $_.Message
            host = $hostName
        }
    }

$snapshot = @{
    collected_at    = (Get-Date).ToUniversalTime().ToString("o")
    source          = "powershell"
    host            = $hostName
    host_role       = "client"
    findings        = @()
    security_events = $securityEvents
    dns_events      = $dnsEvents
    http_events     = $httpEvents
}

$snapshot | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Client snapshot: $OutputPath"
