# Change A User's Password and require for change on login
Param([Parameter(Mandatory=$true)]
    [string]$User,
    [switch]$ChangePasswordAtLogon
)

# Get closest Domain Controller
$DC = (Get-ADDomainController -Discover).hostname

# Prompt for new password and confirm
$newpass = Read-Host -AsSecureString "New Password"
$newpassconf = Read-Host -AsSecureString "Confirm New Password"
    
$newpass_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newpass))
$newpassconf_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newpassconf))

# If password and confirmed password are different, prompt for password again
if ($newpass_text -ceq $newpassconf_text) {
    $newpass_confirmed = $newpass
    } else {
        do{
            Write-Host "Passwords are different, please reenter the password!" -ForegroundColor Yellow
            $newpassretry = Read-Host -AsSecureString "New Password"
            $newpassconftretry = Read-Host -AsSecureString "Confirm New Password"
    
            $newpassretry_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newpassretry))
            $newpassconfretry_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newpassconftretry))
        }
        while($newpassretry_text -ne $newpassconfretry_text)
        $newpass_confirmed = $newpassretry
}

# Resets AD Account Password to your choosing 
Set-ADAccountPassword -Identity $User -NewPassword $newpass_confirmed  -Server $DC -Reset
    
Write-Host "Password has been changed!" -ForegroundColor Green

# Sets account to require change of password on login
if ($ChangePasswordAtLogon.IsPresent){
    Set-ADUser -Identity $User -Server $DC -ChangePasswordAtLogon $True
    Write-Host "Account will need to change password on login!" -ForegroundColor Yellow
}
