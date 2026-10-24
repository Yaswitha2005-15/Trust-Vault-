# demo.ps1 - run from the repo root with the stack up (docker compose up --build -d)
$ErrorActionPreference = "Stop"
$Base = "http://localhost:8080"
$Out = Join-Path $env:TEMP "tv-out.txt"
$Pw = ((Get-Content (Join-Path $PSScriptRoot ".env") | Where-Object { $_ -like "SEED_DEMO_PASSWORD=*" }) -replace "^SEED_DEMO_PASSWORD=","").Trim()
$Tok = @{}
function Jar($who) { Join-Path $env:TEMP "tv-$who.jar" }
function Csrf($who) { (curl.exe -s -b (Jar $who) -c (Jar $who) "$Base/api/auth/csrf" | ConvertFrom-Json).token }
function Step($text) { Write-Host ""; Write-Host "== $text" -ForegroundColor Cyan; Read-Host "Press Enter" | Out-Null }
function Login($who) {
  Remove-Item (Jar $who) -ErrorAction SilentlyContinue
  $t = Csrf $who
  $f = Join-Path $env:TEMP "tv-login.json"
  (@{ email = "$who@trustvault.local"; password = $Pw } | ConvertTo-Json -Compress) | Set-Content -Encoding ascii $f
  $code = curl.exe -s -o $Out -w "%{http_code}" -b (Jar $who) -c (Jar $who) -H "X-XSRF-TOKEN: $t" -H "Content-Type: application/json" --data-binary "@$f" "$Base/api/auth/login"
  Remove-Item $f
  if ($code -ne "200") { throw "Login failed for $who (HTTP $code)" }
  $Tok[$who] = Csrf $who
  Write-Host "$who logged in (HTTP $code)"
}
function Call($who, $method, $path, $body, $form) {
  $a = @("-s","-o",$Out,"-w","%{http_code}","-X",$method,"-b",(Jar $who),"-c",(Jar $who),"-H","X-XSRF-TOKEN: $($Tok[$who])")
  if ($body) {
    $f = Join-Path $env:TEMP "tv-body.json"
    ($body | ConvertTo-Json -Compress) | Set-Content -Encoding ascii $f
    $a += @("-H","Content-Type: application/json","--data-binary","@$f")
  }
  if ($form) { $a += $form }
  $code = & curl.exe @a "$Base$path"
  $len = (Get-Item $Out).Length
  $text = ""
  if ($len -gt 0 -and $len -lt 200000) {
    $first = Get-Content $Out -TotalCount 1
    if ($first -match "^[\{\[]") { $text = Get-Content $Out -Raw }
  }
  Write-Host "$who $method $path -> HTTP $code ($len bytes)"
  if ($text) { Write-Host $text.Substring(0, [Math]::Min(1800, $text.Length)) }
  return [pscustomobject]@{ Code = [int]$code; Text = $text }
}
# A tiny file with a valid PDF signature
$Pdf = Join-Path $env:TEMP "tv-demo.pdf"
[System.IO.File]::WriteAllText($Pdf, "%PDF-1.4`n1 0 obj`n<< /Type /Catalog >>`nendobj`ntrailer`n<< /Root 1 0 R >>`n%%EOF`n")
Step "1. Sign in as owner, viewer and admin (CSRF token, then cookie session)"
Login "owner"; Login "viewer"; Login "admin"
Step "2. Owner uploads a document (validated, stored privately under a generated ID)"
$up = Call "owner" "POST" "/api/documents" $null @("-F","file=@$Pdf;type=application/pdf","-F","title=Demo contract","-F","category=Legal")
if ($up.Code -ne 200 -and $up.Code -ne 201) { throw "Upload failed (HTTP $($up.Code))" }
$docId = ($up.Text | ConvertFrom-Json).id
Write-Host "Document id: $docId"
Step "3. Viewer has no grant: real ID and made-up ID must look identical (404)"
$null = Call "viewer" "GET" "/api/documents/$docId" $null $null
$null = Call "viewer" "GET" "/api/documents/$([guid]::NewGuid())" $null $null
Step "4. Owner grants Read to the viewer, then the viewer downloads (200)"
$g = Call "owner" "POST" "/api/documents/$docId/permissions" @{ userEmail = "viewer@trustvault.local"; level = "Read" } $null
$viewerId = ($g.Text | ConvertFrom-Json).userId
$null = Call "viewer" "GET" "/api/documents/$docId/content" $null $null
Step "5. Owner revokes; the viewer's very next request is refused (404)"
$null = Call "owner" "DELETE" "/api/documents/$docId/permissions/$viewerId" $null $null
$null = Call "viewer" "GET" "/api/documents/$docId/content" $null $null
Step "6. Administrator has no bypass to file contents (404)"
$null = Call "admin" "GET" "/api/documents/$docId/content" $null $null
Step "7. Audit trail (admin): uploads, denials, grant, revoke, with correlation IDs"
$null = Call "admin" "GET" "/api/audit" $null $null
Step "8. Verify the hash chain"
$null = Call "admin" "GET" "/api/audit/verify" $null $null
Write-Host ""
Write-Host "Done. Next: THREATS.md (known gaps) and the mutation result in mutation-output.txt." -ForegroundColor Green
