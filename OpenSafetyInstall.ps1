Set-StrictMode -Version 2

$installpath = 'C:\Program Files\open_safety'
If (-not (Test-Path $installpath)) {
    New-Item -Path $installpath -ItemType Directory
}

Copy-Item .\target\debug\open_safety.exe 'C:\Program Files\open_safety' -Force

#cmd /c assoc .js
# .js=JSFile

cmd /c ftype JSFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"