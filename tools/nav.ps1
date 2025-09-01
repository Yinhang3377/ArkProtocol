# ...existing code...
function _rsfiles {
  Get-ChildItem -Path .\src -Recurse -Filter *.rs | Select-Object -ExpandProperty FullName
}

function gofn($name){
  $pattern = '^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?fn\s+' + [regex]::Escape($name) + '\b'
  $files = _rsfiles
  $m = if($files){ Select-String -Path $files -Pattern $pattern | Select-Object -First 1 }
  if($m){ code -g "$($m.Path):$($m.LineNumber)" } else { Write-Host "not found: $name" }
}

function goconst($name){
  $p1 = '^\s*(?:pub\s+)?const\s+' + [regex]::Escape($name) + '\b'
  $p2 = '(?i)\bconst\s+' + [regex]::Escape($name) + '\b'
  $files = _rsfiles
  $m = $null
  if($files){ $m = Select-String -Path $files -Pattern $p1 | Select-Object -First 1 }
  if(-not $m -and $files){ $m = Select-String -Path $files -Pattern $p2 | Select-Object -First 1 }
  if($m){ code -g "$($m.Path):$($m.LineNumber)" } else { Write-Host "not found: $name" }
}

function go($target){
  if($target -match '^\d+$'){ code -g ".\src\wallet.rs:$target"; return }
  $p = $target -replace '\\','/'
  if(Test-Path ($p.Split(':')[0])){ code -g $target } else { Write-Host "path not found: $target" }
}
# ...existing code...