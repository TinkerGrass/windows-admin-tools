# Windows AD Scripts
All scripts related to Windows AD Administration

## Get-LockOutStatus.ps1
`.\Get-LockOutStatus.ps1 -User $samaccountnamehere -AllLocations`

`-AllLocations` switch is used to unlock user from all Domain Controllers.

## Remove-Computer.ps1
`.\Remove-Computer.ps1 -ComputerObject $COMPUTERNAMEHERE`

## Update-UserPassword.ps1
`.\Update-UserPassword.ps1 -User $username -ChangePasswordAtLogon`

`-ChangePasswordAtLogon` switch is used to require password change at next login for user.
