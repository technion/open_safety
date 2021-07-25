Set-StrictMode -Version 2

# Check for elevation

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "This application must be run as an elevated admin"
    exit
}

$tmpfile = New-TemporaryFile

$installpath = 'C:\Program Files\open_safety'
If (-not (Test-Path $installpath)) {
    New-Item -Path $installpath -ItemType Directory
}

try {
    Invoke-WebRequest "https://github.com/technion/open_safety/releases/latest/download/open_safety.exe" -OutFile $tmpfile.FullName
} catch {
    Write-Output "Failed to download installer"
    exit
}

$signature = Get-AuthenticodeSignature $tmpfile.FullName
if ( $signature.Status -ne 'Valid') {
    Write-Output "Warning: Downloaded file is not signed"
    # Commented out until issues with Sectigo issuing cert are resolved
    #Remove-Item $tmpfile.FullName
    #exit
}

Move-Item $tmpfile.FullName -Destination "$($installpath)\open_safety.exe" -Force
Unblock-File "$($installpath)\open_safety.exe"

# List from application: allowed_extensions = ["js", "jse", "vbs", "wsf", "wsh", "hta"];
# Obtained existing names with: cmd /c assoc .ext
# .js=JSFile
# .jse=JSEFile
# .vbs=VBSFile
# .wsf=WSFFile
# .wsh=WSHFile
# .hta=htafile

Write-Output "Assigning file associations:"
cmd /c ftype JSFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"
cmd /c ftype JSEFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"
cmd /c ftype VBSFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"
cmd /c ftype WSFFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"
cmd /c ftype WSHFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"
cmd /c ftype htafile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"

Write-Output "Open_safety is now active"