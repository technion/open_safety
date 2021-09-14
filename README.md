# Open Safety
An improvement on the "map .js files to notepad" trick

Designed to assist with securing environments by ensuring such blocking events raise significant alarms. For background and more information, see [this blog post](https://lolware.net/blog/neutralising-script-ransomware/)

# Installation
## Enterprise
- Deploy the executable to an appropriate location
- Replace notepad.exe mappings in Group Policies with the new location
## SMB/Home User
- [Download the Release of OpenSafetyInstall.ps1](https://github.com/technion/open_safety/releases/latest/download/OpenSafetyInstall.ps1). This is a signed version of the script in the git tree.
- Run OpenSafetyInstall.ps1 from an elevated Powershell

# Usage

A typical intended deployment involves never manually using this application. The above installation process will configure it to run with suspect files as a parameter. Example:
```
open_safety.exe example.js
```

You may wish to query the version:
```
open_safety.exe --version
```

# Response

This applicaton aims to provide two mechanisms to better handle script execution than the notepad trick. Specifically:

- It provides the user a suitable message, presenting a much less confusing feedback than open a test file of source code
- It attempts to alert any monitoring IT teams

## Details

When this application is executed it will follow the below process, for the script "example.js":

- To prevent any misuse, it first ensures the called file has an appropriate file extension
- It further checks the file does not sit under standard system directories
- The file is renamed to "DANGEROUS example.js.txt" to neutralise the risk.
- It creates the file "example.com" in the same directory containing the EICAR test string. This should set should defenders by setting off appropriate alarms.

## Development

This application currently uses only one external crate (base64). It's designed as much as possible with guard rails around misuse, and it never actually deletes content. CI has been setup with strict use of clippy and cargo fmt. There's a deliberate goal of becoming "stable" and not requiring ongoing addition of features to assist with this becoming trusted for use. To this end, I'm unlikely to accept PRs with substantive changes. Designed to build with rust stable with no unsafe. The binary in "releases" is built straight from this codebase, includes no telemtry or additional code. Currently only Windows x64 type binaries are pre-built for releases.

## TODO

- [X] Installation Powershell to fetch executable from Github releases 
- [X] Implement CI with Github actions
- [X] Blog post on why this is useful
- [X] Obtain a code signing cert

### Release guide
```
cargo build --release
$codeCertificate = Get-ChildItem Cert:\CurrentUser\My
Set-AuthenticodeSignature -FilePath .\target\release\open_safety.exe  -Certificate $codeCertificate -TimeStampServer "http://timestamp.digicert.com"
```
