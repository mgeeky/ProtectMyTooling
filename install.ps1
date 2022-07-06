
Write-Host "`n== Step 1: Installing pip3 dependencies...`n"
pip3 install -r requirements.txt

if ((Get-Command "python2" -ErrorAction SilentlyContinue) -eq $null) 
{
    Write-Error "`nWARNING: Some packers work only on Python2 which you seem to not have installed. Consider installing it to use: peCloakCapstone`n" 
}

if ((Get-Command "nim.exe" -ErrorAction SilentlyContinue) -eq $null) 
{
    Write-Error "`nERROR: For Nim-related packers to work, you need to install Nim on your Windows!`n"
}
else
{
    Write-Host "`n== Step 2: Installs nim dependencies...`n"
    nimble -y install winim nimcrypto docopt ptr_math strenc
}

if ((Get-Command "bash.exe" -ErrorAction SilentlyContinue) -eq $null) 
{
    Write-Error "`nWARNING: You don't seem to have Bash.exe in your Windows (no WSL installed?). Some linux-native packers might not work: ScareCrow`n"  
}

Write-Host "`n`nOK: You should be all set now."
Write-Host "`nEnjoy ProtectMyTooling - and let me know the coolest/most effective packers-chain you come up with! :-)`n" -ForegroundColor green
