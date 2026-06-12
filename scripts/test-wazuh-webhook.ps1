# Test Wazuh webhook → AuthGraph (run from repo root)
$base = if ($env:AUTHGRAPH_URL) { $env:AUTHGRAPH_URL } else { "http://127.0.0.1:8787" }

Write-Host "Ping webhook GET $base/api/webhook/wazuh"
Invoke-RestMethod -Uri "$base/api/webhook/wazuh" | ConvertTo-Json

$payload = Get-Content -Raw "backend/detection/fixtures/wazuh-alert-4769-rc4.json"

Write-Host "`nPOST sample Wazuh 0x17 alert..."
$result = Invoke-RestMethod -Method Post -Uri "$base/api/webhook/wazuh" -ContentType "application/json" -Body $payload
$result | ConvertTo-Json -Depth 5

Write-Host "`nIncidents:"
Invoke-RestMethod -Uri "$base/api/incidents" | ConvertTo-Json -Depth 5
