# Build the L5 manager APK without Gradle (KernelSU-style UI shell).
#
# Host constraints found the hard way:
#   * no Gradle -> drive aapt2 / javac / d8 / zipalign / apksigner directly;
#   * only JDK 8 and JDK 21 are installed, and d8 from build-tools 34 (R8 8.2.2)
#     NPEs on JDK 21 while build-tools 31's d8 uses -Djava.ext.dirs, which JDK 21
#     rejects.  So: javac 8 + build-tools 31 d8, both under JDK 8.
#   * javac 8 on a zh-CN host defaults to GBK, so Chinese literals need
#     -encoding UTF-8.
$ErrorActionPreference = 'Stop'

$sdk  = $(if ($env:ANDROID_SDK) { $env:ANDROID_SDK } else { 'C:\Android\android-sdk' })
$jdk8 = $(if ($env:JAVA8_HOME)  { $env:JAVA8_HOME }  else { 'C:\Program Files\Android\jdk\jdk-8.0.302.8-hotspot\jdk8u302-b08' })
$btA  = Join-Path $sdk 'build-tools\34.0.0'
$btD  = Join-Path $sdk 'build-tools\31.0.0'
$plat = Join-Path $sdk 'platforms\android-31\android.jar'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$out  = Join-Path $root 'build'

foreach ($p in @($btA, $btD, $plat, $jdk8)) {
  if (-not (Test-Path $p)) { throw "missing: $p" }
}

$env:JAVA_HOME = $jdk8
$env:PATH = (Join-Path $jdk8 'bin') + ';' + $env:PATH

Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
$classesDir = Join-Path $out 'classes'
$dexDir     = Join-Path $out 'dex'
New-Item -ItemType Directory -Force -Path $classesDir, $dexDir | Out-Null

$aapt2  = Join-Path $btA 'aapt2.exe'
$zipal  = Join-Path $btA 'zipalign.exe'
$signer = Join-Path $btA 'apksigner.bat'
$d8     = Join-Path $btD 'd8.bat'
$javac  = Join-Path $jdk8 'bin\javac.exe'
$manifest = Join-Path $root 'AndroidManifest.xml'

# ---- aidl: our own user-service interface (Shizuku runs it in a privileged process)
$genDir = Join-Path $out 'gen'
New-Item -ItemType Directory -Force -Path $genDir | Out-Null
$aidlTool = Join-Path $btA 'aidl.exe'
$aidlFiles = @(Get-ChildItem (Join-Path $root 'src') -Recurse -Filter *.aidl |
               ForEach-Object { $_.FullName })
foreach ($a in $aidlFiles) {
  & $aidlTool -o $genDir -I (Join-Path $root 'src') $a
  if ($LASTEXITCODE -ne 0) { throw ("aidl failed: " + $a) }
}

$srcs = @(Get-ChildItem (Join-Path $root 'src') -Recurse -Filter *.java |
          ForEach-Object { $_.FullName })
$srcs += @(Get-ChildItem $genDir -Recurse -Filter *.java | ForEach-Object { $_.FullName })
if ($srcs.Count -eq 0) { throw 'no java sources' }
# ---- official Shizuku client jars (api / provider / shared 13.1.5)
$jars = @(Get-ChildItem (Join-Path $root 'libs') -Filter *.jar |
          ForEach-Object { $_.FullName })
Write-Host ("sources: {0}  shizuku-jars: {1}" -f $srcs.Count, $jars.Count)

Write-Host '=== 1/6 aapt2 link ==='
$unsigned = Join-Path $out 'app-unsigned.apk'
& $aapt2 link -o $unsigned -I $plat --manifest $manifest
if ($LASTEXITCODE -ne 0) { throw 'aapt2 link failed' }

Write-Host '=== 2/6 javac 8 (UTF-8) ==='
$javacArgs = @('-source', '8', '-target', '8', '-encoding', 'UTF-8', '-nowarn',
               '-classpath', ($plat + ';' + ($jars -join ';')), '-d', $classesDir) + $srcs
& $javac @javacArgs
if ($LASTEXITCODE -ne 0) { throw 'javac failed' }

Write-Host '=== 3/6 d8 (build-tools 31 on JDK 8) ==='
$classFiles = @(Get-ChildItem $classesDir -Recurse -Filter *.class |
                ForEach-Object { $_.FullName })
$d8Args = @('--lib', $plat, '--min-api', '31', '--output', $dexDir) + $classFiles + $jars
& $d8 @d8Args
if ($LASTEXITCODE -ne 0) { throw 'd8 failed' }
$dex = Join-Path $dexDir 'classes.dex'
if (-not (Test-Path $dex)) { throw 'no classes.dex' }
Write-Host ("   classes.dex = {0} bytes" -f (Get-Item $dex).Length)

Write-Host '=== 4/6 put classes.dex into the apk ==='
$staged = Join-Path $out 'app-staged.apk'
Copy-Item $unsigned $staged -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
$zip = [System.IO.Compression.ZipFile]::Open($staged, 'Update')
try {
  $entry = $zip.CreateEntry('classes.dex',
            [System.IO.Compression.CompressionLevel]::Optimal)
  $es = $entry.Open()
  try {
    $bytes = [System.IO.File]::ReadAllBytes($dex)
    $es.Write($bytes, 0, $bytes.Length)
  } finally { $es.Dispose() }
} finally { $zip.Dispose() }

Write-Host '=== 5/6 zipalign ==='
$aligned = Join-Path $out 'app-aligned.apk'
Remove-Item $aligned -Force -ErrorAction SilentlyContinue
& $zipal -p -f 4 $staged $aligned
if ($LASTEXITCODE -ne 0) { throw 'zipalign failed' }

Write-Host '=== 6/6 sign ==='
$ks = Join-Path $root 'debug.keystore'
# Keystore lives OUTSIDE build/: $out is wiped on every build, and regenerating
# the key makes install fail with INSTALL_FAILED_UPDATE_INCOMPATIBLE while the
# old APK silently stays installed.
if (-not (Test-Path $ks)) {
  & (Join-Path $jdk8 'bin\keytool.exe') -genkeypair -keystore $ks `
      -storepass android -keypass android -alias androiddebugkey `
      -dname 'CN=L5,O=L5,C=CN' -keyalg RSA -keysize 2048 -validity 10000 | Out-Null
}
$final = Join-Path $out 'l5root.apk'
Remove-Item $final -Force -ErrorAction SilentlyContinue
& $signer sign --ks $ks --ks-pass pass:android --key-pass pass:android `
    --out $final $aligned
if ($LASTEXITCODE -ne 0) { throw 'apksigner failed' }

& $signer verify $final
$fi = Get-Item $final
Write-Host ("APK OK: {0}  size={1} bytes" -f $fi.FullName, $fi.Length)
