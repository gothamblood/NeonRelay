<#
  NeonRelay — installation du client Windows (une seule fois, sans droits administrateur).

  Lancer : double-clic sur install.cmd
     ou : powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1

  Ce que fait ce script, dans %LOCALAPPDATA%\NeonRelay :
    1. télécharge le Python OFFICIEL (python.org, « embeddable », OpenSSL 3.5 :
       ML-DSA-87 + ML-KEM) et PyNaCl + ses dépendances (PyPI) ;
    2. vérifie l'empreinte SHA-256 de CHAQUE téléchargement (fixée ci-dessous)
       et la signature Authenticode de python.exe (Python Software Foundation) ;
    3. copie neonrelay.py + openssl-tls.cnf (dossier client\, parent de celui-ci) ;
    4. ajoute « neonrelay » au PATH de l'utilisateur : Win+R → neonrelay.

  Rien n'est installé dans le système, aucune clé de registre n'est créée.
  Désinstaller : uninstall.cmd.
#>
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # la barre de progression ralentit énormément les téléchargements

# Téléchargements (python.org, PyPI) en TLS 1.2 minimum : TLS 1.0 / 1.1 refusés
# même si .NET ou Windows les autorisent encore. TLS 1.3 ajouté si ce .NET le
# connaît (Windows 11) ; pas « 1.3 seul » : Windows 10 n'a pas TLS 1.3 de base.
# L'intégrité, elle, repose sur les empreintes SHA-256 ci-dessous.
$tls = [Net.SecurityProtocolType]::Tls12
if ([enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
  $tls = $tls -bor [Net.SecurityProtocolType]::Tls13
}
[Net.ServicePointManager]::SecurityProtocol = $tls

# Le client (neonrelay.py + openssl-tls.cnf) est commun à Windows et Linux :
# il est dans client/, le dossier parent de client/windows/.
$Here = Split-Path -Parent $PSScriptRoot
$Dest = Join-Path $env:LOCALAPPDATA 'NeonRelay'
$Py   = Join-Path $Dest 'python'
$Bin  = Join-Path $Dest 'bin'

# Téléchargements épinglés : une empreinte différente = installation annulée.
# Mettre à jour une version = changer l'URL ET l'empreinte (publiées par python.org / PyPI).
$Python = @{
  Name   = 'python-3.15.2-embed-amd64.zip'
  Url    = 'https://www.python.org/ftp/python/3.15.2/python-3.15.2-embed-amd64.zip'
  Sha256 = 'd012f3aa29cf07436dae8aea1fec0fd195c2612a0b059b1f915ae0afb9ad1f62'
}
$Wheels = @(
  @{
    Name   = 'pynacl-1.6.2-cp38-abi3-win_amd64.whl'
    Url    = 'https://files.pythonhosted.org/packages/41/ad/334600e8cacc7d86587fe5f565480fde569dfb487389c8e1be56ac21d8ac/pynacl-1.6.2-cp38-abi3-win_amd64.whl'
    Sha256 = '62985f233210dee6548c223301b6c25440852e13d59a8b81490203c3227c5ba0'
  },
  @{
    Name   = 'cffi-2.1.1-cp315-cp315-win_amd64.whl'
    Url    = 'https://files.pythonhosted.org/packages/e0/31/5158704cc474ab65c1647932e88be78dc0873f47130e253be38bcaf13d01/cffi-2.1.1-cp315-cp315-win_amd64.whl'
    Sha256 = 'e6e8cff14d6fb0be70a09c0bdc58096f501952d04624ebf867e0e56da2df8960'
  }
)
# pycparser n'est PAS installé : il ne sert qu'à compiler des modules cffi, or
# PyNaCl est livré précompilé (prouvé sous Linux, T-17 ; vérifié ci-dessous).

function Get-Verified($Item, $Dir) {
  $out = Join-Path $Dir $Item.Name
  Write-Host "  - $($Item.Name)"
  Invoke-WebRequest -Uri $Item.Url -OutFile $out -UseBasicParsing
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $out).Hash.ToLowerInvariant()
  if ($hash -ne $Item.Sha256) {
    throw "Empreinte SHA-256 inattendue pour $($Item.Name) : téléchargement altéré, installation annulée."
  }
  return $out
}

foreach ($f in 'neonrelay.py', 'openssl-tls.cnf') {
  if (-not (Test-Path -LiteralPath (Join-Path $Here $f))) {
    throw "$f introuvable dans $Here : garde le dossier client complet (client\windows\install.cmd + client\$f)."
  }
}

Write-Host 'NeonRelay — installation du client'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('neonrelay-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host 'Téléchargement (empreintes SHA-256 vérifiées) :'
  $pyZip = Get-Verified $Python $tmp
  $wheelFiles = foreach ($w in $Wheels) { Get-Verified $w $tmp }

  if (Test-Path -LiteralPath $Py) { Remove-Item -LiteralPath $Py -Recurse -Force }
  New-Item -ItemType Directory -Force -Path $Py, $Bin | Out-Null
  Expand-Archive -LiteralPath $pyZip -DestinationPath $Py

  # Deuxième verrou, indépendant de l'empreinte : python.exe signé par la PSF.
  $sig = Get-AuthenticodeSignature -LiteralPath (Join-Path $Py 'python.exe')
  if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
    throw "Signature de python.exe invalide ($($sig.Status)) : installation annulée."
  }

  # Une roue (.whl) est une archive zip : on la décompresse à côté de python.exe,
  # dossier déjà dans le chemin d'import du Python embarqué (« . » du fichier ._pth).
  foreach ($whl in $wheelFiles) {
    $zip = [IO.Path]::ChangeExtension($whl, '.zip')
    Copy-Item -LiteralPath $whl -Destination $zip
    Expand-Archive -LiteralPath $zip -DestinationPath $Py -Force
  }

  Copy-Item -LiteralPath (Join-Path $Here 'neonrelay.py'), (Join-Path $Here 'openssl-tls.cnf') -Destination $Dest -Force

  Set-Content -LiteralPath (Join-Path $Bin 'neonrelay.cmd') -Encoding ASCII -Value @(
    '@echo off',
    '"%LOCALAPPDATA%\NeonRelay\python\python.exe" -I "%LOCALAPPDATA%\NeonRelay\neonrelay.py" %*'
  )

  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not $userPath) { $userPath = '' }
  if (($userPath -split ';') -notcontains $Bin) {
    $newPath = (($userPath.TrimEnd(';'), $Bin) | Where-Object { $_ }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
  }

  Write-Host 'Vérification :'
  & (Join-Path $Py 'python.exe') -I -c "import ssl, nacl.secret, nacl.pwhash, nacl.utils; nacl.secret.SecretBox(nacl.pwhash.argon2id.kdf(32, b'x', nacl.utils.random(16), opslimit=2, memlimit=8388608)).encrypt(b'x'); print('  ' + ssl.OPENSSL_VERSION + ' + PyNaCl OK')"
  if ($LASTEXITCODE -ne 0) { throw 'Le Python installé ne démarre pas correctement.' }

  Write-Host ''
  Write-Host 'Installé. Branche le Digispark (ou Win+R → neonrelay, puis colle la clé).'
  Write-Host 'Si Win+R ne trouve pas « neonrelay », ferme la session Windows et rouvre-la.'
}
finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
