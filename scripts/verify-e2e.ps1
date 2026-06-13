# End-to-end verification for AuthGraph ITDR MVP
$ErrorActionPreference = "Stop"
$base = if ($env:AUTHGRAPH_URL) { $env:AUTHGRAPH_URL } else { "http://127.0.0.1:8787" }

Write-Host "`n=== AuthGraph ITDR E2E Verification ===" -ForegroundColor Cyan
Write-Host "API: $base`n"

function Test-Endpoint($Name, $Uri, $Method = "GET", $Body = $null) {
  try {
    $params = @{ Uri = $Uri; Method = $Method; ContentType = "application/json" }
    if ($Body) { $params.Body = $Body }
    $r = Invoke-RestMethod @params
    Write-Host "[OK] $Name" -ForegroundColor Green
    return $r
  } catch {
    Write-Host "[FAIL] $Name — $($_.Exception.Message)" -ForegroundColor Red
    return $null
  }
}

$h = Test-Endpoint "Health" "$base/api/health"
if (-not $h) { Write-Host "`nStart backend: npm run dev`n"; exit 1 }

$verify = Test-Endpoint "MVP verify" "$base/api/verify"
if ($verify) {
  Write-Host "`nMVP checklist:" -ForegroundColor Yellow
  $verify.mvp.PSObject.Properties | ForEach-Object {
    $icon = if ($_.Value) { "PASS" } else { "FAIL" }
    $color = if ($_.Value) { "Green" } else { "Red" }
    Write-Host "  [$icon] $($_.Name)" -ForegroundColor $color
  }
  Write-Host "`nDetailed checks ($($verify.passed)/$($verify.total)):" -ForegroundColor Yellow
  $verify.checks | ForEach-Object {
    $icon = if ($_.pass) { "+" } else { "-" }
    Write-Host "  [$icon] $($_.name) — $($_.detail)"
  }
}

Test-Endpoint "Sigma library" "$base/api/sigma/rules" | Out-Null
Test-Endpoint "Explain incident" "$base/api/explain/alert-001" | Out-Null

Write-Host "`nWebhook replay (Wazuh fixture)..." -ForegroundColor Yellow
$payload = Get-Content -Raw "$PSScriptRoot\..\backend\detection\fixtures\wazuh-alert-4769-rc4.json"
$ingest = Test-Endpoint "Wazuh webhook POST" "$base/api/webhook/wazuh" "POST" $payload
if ($ingest -and $ingest.ok) {
  Write-Host "  Incident risk: $($ingest.incident.risk) target: $($ingest.incident.target)" -ForegroundColor Gray
}

Write-Host "`nBackend unit tests..." -ForegroundColor Yellow
Push-Location "$PSScriptRoot\..\backend"
node detection/detection.test.js
if ($LASTEXITCODE -ne 0) { Pop-Location; exit $LASTEXITCODE }
node test/api.test.js
$testExit = $LASTEXITCODE
Pop-Location

if ($verify -and $verify.ok -and $testExit -eq 0) {
  Write-Host "`n=== ALL MVP REQUIREMENTS VERIFIED ===" -ForegroundColor Green
  exit 0
}

Write-Host "`n=== SOME CHECKS FAILED — review output above ===" -ForegroundColor Red
exit 1
