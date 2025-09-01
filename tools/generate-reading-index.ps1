param(
  [string] $Out = ".\docs\reading-index.md"
)

function Encode-PathForVSCode {
  param([string]$p)
  $p2 = $p -replace '\\','/'
  $segments = $p2 -split '/'
  ($segments | ForEach-Object { [System.Uri]::EscapeDataString($_) }) -join '/'
}

$root  = (Resolve-Path .).Path
$files = Get-ChildItem -Path .\src -Recurse -Filter *.rs | Select-Object -ExpandProperty FullName

# 收集到简单数组，避免 .Add()
$lines = @()
$lines += "# Ark Protocol Reading Index"
$lines += ""
$lines += "- Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$lines += "- Tip: Ctrl+Click links to open in VS Code"
$lines += ""

foreach ($file in $files) {
  $abs = (Resolve-Path $file).Path
  if ($abs.StartsWith($root)) { $rel = $abs.Substring($root.Length + 1) } else { $rel = $abs }
  $lines += "## .\" + $rel

  # const
  $constPattern = '^\s*(?:pub\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)\s*[:=]'
  $consts = Select-String -Path $file -Pattern $constPattern
  if ($consts) {
    $lines += "### const"
    foreach ($m in $consts) {
      $name = $m.Matches[0].Groups[1].Value
      $ln   = $m.LineNumber
      $link = "vscode://file/" + (Encode-PathForVSCode $abs) + ":" + $ln
      $lines += "- [" + $name + "](" + $link + ")  " + $rel + ":" + $ln
    }
  }

  # fn (支持 pub(crate), async)
  $fnPattern = '^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)'
  $fns = Select-String -Path $file -Pattern $fnPattern
  if ($fns) {
    $lines += "### fn"
    foreach ($m in $fns) {
      $name = $m.Matches[0].Groups[1].Value
      $ln   = $m.LineNumber
      $link = "vscode://file/" + (Encode-PathForVSCode $abs) + ":" + $ln
      $lines += "- [" + $name + "](" + $link + ")  " + $rel + ":" + $ln
    }
  }

  $lines += ""
}

New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
# 用 UTF-8 BOM 写出，避免乱码
Set-Content -Path $Out -Value $lines -Encoding utf8
Write-Host "Done -> $Out"