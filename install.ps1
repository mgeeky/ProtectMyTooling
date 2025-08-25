
Write-Host "`n== Step 1: Installing pip3 dependencies...`n" -ForegroundColor cyan
python -m venv venv
.\venv\Scripts\activate

pip3 install -r requirements.txt
python -m pip install --upgrade --extra-index-url https://PySimpleGUI.net/install PySimpleGUI

if ((Get-Command "python2" -ErrorAction SilentlyContinue) -eq $null) 
{
    Write-Host "`nWARNING: Some packers work only on Python2 which you seem to not have installed. Consider installing it to use: peCloakCapstone`n" -ForegroundColor yellow 
}

if ((Get-Command "nim.exe" -ErrorAction SilentlyContinue) -eq $null) 
{
    Write-Host "`nERROR: For Nim-related packers to work, you need to install Nim on your Windows! Consider using Chocolatey manager: choco install nim -y`n" -ForegroundColor green
}
else
{
    Write-Host "`n== Step 2a: Installs nim dependencies...`n" -ForegroundColor cyan
    nimble -y install winim nimcrypto docopt ptr_math strenc

    Write-Host "`n== Step 2b: Installs denim.exe (github.com/moloch--/denim) dependencies...`n" -ForegroundColor cyan
    .\contrib\denim\denim.exe setup
}

if ((Get-Command "bash.exe" -ErrorAction SilentlyContinue) -eq $null) 
{
    Write-Host "`nWARNING: You don't seem to have Bash.exe in your Windows (no WSL installed?). Some linux-native packers might not work: ScareCrow`n"  -ForegroundColor green 
}
else
{
    Write-Host "`n`n== Step 3: Installing Linux dependencies (via WSL bash.exe). You'll be asked for sudo password...`n`n" -ForegroundColor cyan
    bash.exe -c "sudo apt install -y dos2unix ; dos2unix install.sh"
    bash.exe install.sh
}

Write-Host "`n`nOK: You should be all set now.`n"
Write-Host "`nEnjoy ProtectMyTooling - and let me know the coolest/most effective packers-chain you come up with! :-)`n" -ForegroundColor green
