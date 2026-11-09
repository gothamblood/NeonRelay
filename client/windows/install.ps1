<#
  NeonRelay — installation du client Windows (une seule fois, sans droits administrateur).

  Deux façons de le lancer :
    - AMORÇAGE (cas normal) : le Digispark tape une commande qui télécharge ce
      script, vérifie son SHA-256 contre l'empreinte gravée dans la clé, puis
      l'exécute avec -Source URL. Le client n'a jamais le dossier client\.
    - LOCAL (opérateur) : double-clic sur install.cmd, ou
      powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1

  Ce que fait ce script, dans %LOCALAPPDATA%\NeonRelay :
    1. télécharge le Python OFFICIEL (python.org, « embeddable », OpenSSL 3.5 :
       ML-DSA-87 + ML-KEM) et PyNaCl + cffi (PyPI) ;
    2. récupère neonrelay.py + openssl-tls.cnf (depuis -Source, sinon depuis
       le dossier parent client\) ;
    3. vérifie l'empreinte SHA-256 de CHAQUE fichier (fixée ci-dessous) et la
       signature Authenticode de python.exe (Python Software Foundation) ;
    4. ajoute « neonrelay » au PATH de l'utilisateur.

  Chaîne de confiance : empreinte de CE fichier (dans la clé) → empreintes
  ci-dessous → chaque fichier installé. Après toute modification de
  neonrelay.py ou openssl-tls.cnf : client/epingler.sh.

  Rien n'est installé dans le système, aucune clé de registre n'est créée.
  Désinstaller : uninstall.cmd.
#>
param(
  # URL du dossier client (contient neonrelay.py et openssl-tls.cnf), sans « / » final.
  # Vide = copie locale depuis le dossier parent de ce script.
  [string]$Source = ''
)
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

# Le client lui-même. Empreintes mises à jour par client/epingler.sh.
$ClientFiles = @(
  @{ Name = 'neonrelay.py'; Sha256 = '5d59aa458fc558e82ed56c597b2061a00664d7d8e14a041d6f873231c1ede5fc' },
  @{ Name = 'openssl-tls.cnf'; Sha256 = '40fcb1b909e540eae22417442fa6e081ac6eff53d14d72cfbe43362a398de2ad' }
)

function Get-Verified($Item, $Dir) {
  $out = Join-Path $Dir $Item.Name
  Write-Host "  - $($Item.Name)"
  if ($Item.Url) {
    Invoke-WebRequest -Uri $Item.Url -OutFile $out -UseBasicParsing
  } else {
    Copy-Item -LiteralPath $Item.Path -Destination $out
  }
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $out).Hash.ToLowerInvariant()
  if ($hash -ne $Item.Sha256) {
    throw "Empreinte SHA-256 inattendue pour $($Item.Name) : téléchargement altéré, installation annulée."
  }
  return $out
}

$Source = $Source.TrimEnd('/')
foreach ($c in $ClientFiles) {
  if ($Source) {
    $c.Url = "$Source/$($c.Name)"
  } else {
    $c.Path = Join-Path $Here $c.Name
    if (-not (Test-Path -LiteralPath $c.Path)) {
      throw "$($c.Name) introuvable dans $Here : garde le dossier client complet (client\windows\install.cmd + client\$($c.Name))."
    }
  }
}

Write-Host 'NeonRelay — première utilisation : installation du client (1 à 2 minutes).'
Write-Host 'Ne touche à rien : la clé fait tout. Chaque fichier est vérifié avant usage.'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('neonrelay-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host 'Téléchargement (empreintes SHA-256 vérifiées) :'
  $pyZip = Get-Verified $Python $tmp
  $wheelFiles = foreach ($w in $Wheels) { Get-Verified $w $tmp }
  $clientPaths = foreach ($c in $ClientFiles) { Get-Verified $c $tmp }

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

  Copy-Item -LiteralPath $clientPaths -Destination $Dest -Force

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
  if ($Source) {
    Write-Host 'Installé. Lancement du client…'   # l'amorçage enchaîne sur neonrelay.cmd
  } else {
    Write-Host 'Installé. Branche le Digispark (ou Win+R → neonrelay, puis colle la clé).'
    Write-Host 'Si Win+R ne trouve pas « neonrelay », ferme la session Windows et rouvre-la.'
  }
}
finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
