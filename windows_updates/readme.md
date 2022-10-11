# Windows Update Scripts

- Kick off Windows Updates remotely using PSWindowsUpdate PowerShell Module and Task Scheduler on target host
    - `.\Invoke-RemotePSWU.ps1 -ComputerName $FQDN -AutoReboot`
    - Remove `-AutoReboot` to not kick off reboot of target host
    - Will ask for credentials that have admin rights on target host
    - Remember to change ORGNAME to something of your choosing
