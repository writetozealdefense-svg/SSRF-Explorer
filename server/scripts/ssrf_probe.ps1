<#
  ssrf_probe.ps1 — Windows PowerShell SSRF probe.

  Reads a single-line JSON request from stdin:
    {
      "method":  "GET" | "POST" | ...,
      "url":     "https://target/...",
      "headers": { "Header": "value", ... },
      "body":    "raw body or empty",
      "param":   { "name": "...", "location": "query|body-form|body-json|header" },
      "payload": "http://127.0.0.1/...",
      "timeout": 10,
      "proxy":   "http://127.0.0.1:8080" (optional — route via Burp)
    }

  Writes exactly one JSON line to stdout:
    { "status": <int>, "elapsed_ms": <int>, "headers": {...},
      "body_excerpt": "...", "redirect": "...", "error": "..." }

  Runs on both Windows PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
try {
  [Net.ServicePointManager]::SecurityProtocol =
    [Net.SecurityProtocolType]::Tls12 -bor
    [Net.SecurityProtocolType]::Tls11 -bor
    [Net.SecurityProtocolType]::Tls
} catch {}

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue | Out-Null

$raw = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($raw)) {
  '{"status":0,"elapsed_ms":0,"headers":{},"body_excerpt":"","redirect":"","error":"no input"}'
  exit 1
}

try { $req = $raw | ConvertFrom-Json } catch {
  '{"status":0,"elapsed_ms":0,"headers":{},"body_excerpt":"","redirect":"","error":"bad json"}'
  exit 1
}

function ToHash($obj) {
  $h = @{}
  if (-not $obj) { return $h }
  if ($obj -is [hashtable]) { foreach ($k in $obj.Keys) { $h[$k] = $obj[$k] }; return $h }
  foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = $p.Value }
  return $h
}

function Mutate {
  param($Url, $Body, $Headers, $Spec, $Payload, $Method)
  # Every branch returns an object with Url/Body/Headers; Method override is
  # optional — most locations don't change the verb.
  switch ($Spec.location) {
    'query' {
      $ub = [System.UriBuilder]::new($Url)
      $qs = [System.Web.HttpUtility]::ParseQueryString($ub.Query)
      $qs[$Spec.name] = $Payload
      $ub.Query = $qs.ToString()
      return @{ Url = $ub.Uri.AbsoluteUri; Body = $Body; Headers = $Headers }
    }
    'body-form' {
      $pairs = @{}
      if ($Body) {
        foreach ($p in $Body.Split('&')) {
          $kv = $p.Split('=', 2)
          if ($kv.Length -eq 2) { $pairs[$kv[0]] = $kv[1] }
        }
      }
      $pairs[$Spec.name] = [System.Uri]::EscapeDataString($Payload)
      $new = ($pairs.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
      return @{ Url = $Url; Body = $new; Headers = $Headers }
    }
    'body-json' {
      if ($PSVersionTable.PSVersion.Major -ge 6) {
        try { $obj = $Body | ConvertFrom-Json -AsHashtable -ErrorAction Stop } catch { $obj = @{} }
      } else {
        try {
          $pobj = $Body | ConvertFrom-Json -ErrorAction Stop
          $obj = @{}
          foreach ($p in $pobj.PSObject.Properties) { $obj[$p.Name] = $p.Value }
        } catch { $obj = @{} }
      }
      $obj[$Spec.name] = $Payload
      $new = $obj | ConvertTo-Json -Compress -Depth 10
      return @{ Url = $Url; Body = $new; Headers = $Headers }
    }
    'body-inject' {
      # API3 / BOPLA mass assignment: add a NEW field to the body without
      # replacing anything else. JSON if content-type looks like it.
      $h = ToHash $Headers
      $ctype = ''
      foreach ($k in $h.Keys) { if ($k -match '^content-type$') { $ctype = "$($h[$k])"; break } }
      if ($ctype -match 'application/json' -or ($Body -and $Body.TrimStart().StartsWith('{'))) {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
          try { $obj = $Body | ConvertFrom-Json -AsHashtable -ErrorAction Stop } catch { $obj = @{} }
        } else {
          try {
            $pobj = $Body | ConvertFrom-Json -ErrorAction Stop
            $obj = @{}
            foreach ($p in $pobj.PSObject.Properties) { $obj[$p.Name] = $p.Value }
          } catch { $obj = @{} }
        }
        $obj[$Spec.name] = $Payload
        $new = $obj | ConvertTo-Json -Compress -Depth 10
        if (-not $h.ContainsKey('Content-Type')) { $h['Content-Type'] = 'application/json' }
        return @{ Url = $Url; Body = $new; Headers = $h }
      } else {
        $suffix = "$([System.Uri]::EscapeDataString($Spec.name))=$([System.Uri]::EscapeDataString([string]$Payload))"
        $new = if ($Body) { "$Body&$suffix" } else { $suffix }
        return @{ Url = $Url; Body = $new; Headers = $h }
      }
    }
    'header' {
      $h = ToHash $Headers
      $h[$Spec.name] = $Payload
      return @{ Url = $Url; Body = $Body; Headers = $h }
    }
    'header-remove' {
      # Strip one or more headers named in $Spec.name (comma-separated).
      $drop = @($Spec.name -split ',' | ForEach-Object { $_.Trim().ToLower() })
      $h = @{}
      $src = ToHash $Headers
      foreach ($k in $src.Keys) {
        if ($drop -notcontains $k.ToLower()) { $h[$k] = $src[$k] }
      }
      return @{ Url = $Url; Body = $Body; Headers = $h }
    }
    'method' {
      # Payload is the new HTTP method. Body/Headers unchanged.
      return @{ Url = $Url; Body = $Body; Headers = $Headers; Method = $Payload }
    }
    'path-swap' {
      # Payload is the new absolute path (+query) for the same host.
      try {
        $u = [Uri]$Url
        $authority = $u.GetLeftPart([System.UriPartial]::Authority)
        $newUrl = "$authority$Payload"
        return @{ Url = $newUrl; Body = $Body; Headers = $Headers }
      } catch {
        return @{ Url = $Url; Body = $Body; Headers = $Headers }
      }
    }
    'none' {
      # Baseline / no mutation — the probe is sent as-is.
      return @{ Url = $Url; Body = $Body; Headers = $Headers }
    }
    default {
      return @{ Url = $Url; Body = $Body; Headers = $Headers }
    }
  }
}

$prep = Mutate -Url $req.url -Body $req.body -Headers $req.headers -Spec $req.param -Payload $req.payload -Method $req.method
$effectiveMethod = if ($prep.Method) { $prep.Method } else { $req.method }

$hdrs = @{}
if ($prep.Headers) {
  if ($prep.Headers -is [hashtable]) { $hdrs = $prep.Headers }
  else { foreach ($p in $prep.Headers.PSObject.Properties) { $hdrs[$p.Name] = $p.Value } }
}
foreach ($drop in @('Host','Content-Length','Connection','Accept-Encoding')) {
  if ($hdrs.ContainsKey($drop)) { [void]$hdrs.Remove($drop) }
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$status = 0
$respHeaders = @{}
$bodyExcerpt = ''
$redirect = ''
$err = $null

# PS 5.1 has no SkipCertificateCheck; install a permissive validator once.
if ($PSVersionTable.PSVersion.Major -lt 6) {
  try {
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  } catch {}
}

try {
  $params = @{
    Uri                 = $prep.Url
    Method              = $effectiveMethod
    Headers             = $hdrs
    TimeoutSec          = [int]$req.timeout
    MaximumRedirection  = 0
    UseBasicParsing     = $true
    ErrorAction         = 'Stop'
  }
  if ($req.proxy) { $params.Proxy = $req.proxy }
  if ($prep.Body -and $effectiveMethod -notin @('GET','HEAD')) { $params.Body = $prep.Body }
  if ($PSVersionTable.PSVersion.Major -ge 6) {
    $params.SkipCertificateCheck = $true
    $params.SkipHttpErrorCheck = $true
  }
  $resp = Invoke-WebRequest @params
  $status = [int]$resp.StatusCode
  foreach ($h in $resp.Headers.GetEnumerator()) {
    $v = $h.Value
    if ($v -is [array]) { $v = ($v -join ', ') }
    $respHeaders[$h.Key] = "$v"
  }
  if ($respHeaders.ContainsKey('Location')) { $redirect = $respHeaders['Location'] }
  $content = if ($resp.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($resp.Content) } else { [string]$resp.Content }
  if ($content.Length -gt 4096) { $bodyExcerpt = $content.Substring(0, 4096) } else { $bodyExcerpt = $content }
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
