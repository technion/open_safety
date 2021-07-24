Set-StrictMode -Version 2

$installpath = 'C:\Program Files\open_safety'
If (-not (Test-Path $installpath)) {
    New-Item -Path $installpath -ItemType Directory
}

Copy-Item .\target\debug\open_safety.exe 'C:\Program Files\open_safety' -Force

# List from application: allowed_extensions = ["js", "jse", "vbs", "wsf", "wsh", "hta"];
# Obtained existing names with: cmd /c assoc .ext
# .js=JSFile
# .jse=JSEFile
# .vbs=VBSFile
# .wsf=WSFFile
# .wsh=WSHFile
# .hta=htafile

cmd /c ftype JSFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"
cmd /c ftype JSEFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"
cmd /c ftype VBSFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"
cmd /c ftype WSFFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"
cmd /c ftype WSHFile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"
cmd /c ftype htafile=`"C:\Program Files\open_safety\open_safety.exe`" `"%1`"