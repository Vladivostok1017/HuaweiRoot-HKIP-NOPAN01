# 编译 payload：preload.so + su_daemon
#
#   .\build.ps1                     # 用 $env:ANDROID_NDK 或默认 NDK 路径
#   .\build.ps1 -Ndk D:\ndk\r27c    # 显式指定
#
# 产物：
#   build\nop_nop_an01p\bin\preload.so              注入用的 .so（红线 161144 字节）
#   build\embed\su_daemon_aarch64_pie               落地后拉起的目标进程
#
# 为什么直接调 clang 而不用 Makefile：上游 Makefile 按 target 名选片，
# 这里只有一个 target（nop_nop_an01p），走 NDK clang 最短。
param(
  [string]$Ndk = $(if ($env:ANDROID_NDK) { $env:ANDROID_NDK } else { 'C:\Android\android-ndk-r27c' }),
  [string]$Api = '35'
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$src  = Join-Path $root 'src'

if (-not (Test-Path $src)) { throw "missing: $src" }

$tc      = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64'
$cc      = Join-Path $tc 'bin\clang.exe'
$sysroot = Join-Path $tc 'sysroot'
$resdir  = Join-Path $tc 'lib\clang\18'
foreach ($p in @($cc, $sysroot, $resdir)) {
  if (-not (Test-Path $p)) { throw "missing: $p  (用 -Ndk 指定 NDK 根目录)" }
}

$tgt = @(
  "--target=aarch64-linux-android$Api",
  "--sysroot=$sysroot",
  '-resource-dir', $resdir,
  '--rtlib=compiler-rt',
  '--unwindlib=none'
)
$ldf = @(
  '-fuse-ld=lld',
  "-Wl,-rpath-link,$sysroot/usr/lib/aarch64-linux-android/$Api",
  "-L$sysroot/usr/lib/aarch64-linux-android/$Api",
  "-L$sysroot/usr/lib/aarch64-linux-android"
)
$def = '-DTARGET_CONFIG_H=<targets/nop_nop_an01p/target.h>'

$buildEmbed = Join-Path $root 'build\embed'
$buildBin   = Join-Path $root 'build\nop_nop_an01p\bin'
New-Item -ItemType Directory -Force -Path $buildEmbed, $buildBin | Out-Null

Write-Host '=== step 1: su_daemon PIE ==='
$suArgs = @($tgt) + @('-fPIE','-pie','-O2','-g0','-Wall','-Wextra','-Isrc',$def,
            'src/su_daemon.c') + @($ldf) +
          @('-Wl,-dynamic-linker,/system/bin/linker64','-o','build/embed/su_daemon_aarch64_pie')
Push-Location $root
try { & $cc @suArgs } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw 'su_daemon build failed' }
$su = Join-Path $buildEmbed 'su_daemon_aarch64_pie'
Write-Host ("su_daemon ok  size={0}" -f (Get-Item $su).Length)

Write-Host '=== step 2: preload.so ==='
$soArgs = @($tgt) + @('-fPIC','-O2','-g0','-Wall','-Wextra','-Isrc',$def,
            '-Wno-unused-parameter','-Wno-sign-compare','-Wno-unused-function') +
          @('src/main.c','src/util.c','src/slide.c','src/fops.c','src/pipe.c','src/root.c',
            'src/preload.c','src/wallpaper_blob.S') +
          @($ldf) + @('-shared','-o','build/nop_nop_an01p/bin/preload.so','-pthread')
Push-Location $root
try { & $cc @soArgs } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw 'preload.so build failed' }

$so = Join-Path $buildBin 'preload.so'
$len = (Get-Item $so).Length
Write-Host ("preload.so ok  size={0}  (limit 161144)" -f $len)
if ($len -gt 161144) { Write-Warning 'preload.so 超过 161144 字节红线，注入会失败' }
Get-FileHash $so -Algorithm SHA256 | Select-Object -ExpandProperty Hash
