<#
    .DESCRIPTION
    Target remote host and install Windows Updates using PSWU
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerName,
    [switch]$AutoReboot
)

$Creds = Get-Credential

# Install Module and then kick off Windows Updates
Invoke-Command -ComputerName $ComputerName -Credential $Creds -UseSSL -ScriptBlock {
    ## Install PSWU ##
    if(!(Get-Module -ListAvailable -Name PSWindowsUpdate)){
        Write-Host "PSWindowsUpdate Module not installed on $env:COMPUTERNAME, installing . . .`n" -ForegroundColor Yellow
    
        #TLS Setting
        Write-Host "Setting TLS 1.2 on $env:COMPUTERNAME . . .`n" -ForegroundColor Yellow
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
        # Install NuGet
        Write-Host "Installing NuGet provider on $env:COMPUTERNAME . . .`n" -ForegroundColor Yellow
        Install-PackageProvider -name NuGet -Force
    
        # Trust PowerShell Gallery
        Write-Host "Trusting PSGallery on $env:COMPUTERNAME . . .`n" -ForegroundColor Yellow
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    
    
        Set-ExecutionPolicy bypass -Scope Process -Force -ErrorAction SilentlyContinue
        Install-Module PSWindowsUpdate -Force
        Import-Module PSWindowsUpdate -Force
    }
    elseif (Get-Module -ListAvailable -Name PSWindowsUpdate) {
        Write-Host "PSWindows Update is installed on $env:COMPUTERNAME, Importing  . . .`n" -ForegroundColor Green
        Set-ExecutionPolicy bypass -Scope Process -Force -ErrorAction SilentlyContinue
        Import-Module PSWindowsUpdate -Force
    }

    ## Setup Ahikko task folder if it doesn't exist ##
    $scheduleObject = New-Object -ComObject schedule.service
    $scheduleObject.connect()
    
    try{
        $scheduleObject.GetFolder("\Ahikko")
    }catch{
        $errormessage = $_.Exception.Message
        if($errormessage -like "The system cannot find the file specified. (0x80070002)"){
            # Creating Ahikko task folder if it doesn't exist
            Write-Host "Creating Ahikko task folder as it doesn't exist on $env:COMPUTERNAME . . .`n" -Foregroundcolor Yellow
            $rootFolder = $scheduleObject.GetFolder("\")
            $rootFolder.CreateFolder("Ahikko")
        }elseif($errormessage -like "Cannot create a file when that file already exists. (0x800700B7)"){
            Write-Host "Ahikko task folder already exists on $env:COMPUTERNAME . . .`n" -Foregroundcolor Green
        }
    }
    
    

    ## PSWU Scheduled Task Creation ##
    $PSWUTaskArg = "-Command `"Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process;Import-Module PSWindowsUpdate; Get-WUInstall -AcceptAll -Install -IgnoreReboot -Verbose | Out-File -FilePath 'C:\PSWU.log'"""
    $PSWUSchTaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "$PSWUTaskArg"
    $PSWUSchTaskTrigger = New-ScheduledTaskTrigger -Once -At "12AM"
    $PSWUSchTaskPrincipal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $PSWUSchTaskSetting = New-ScheduledTaskSettingsSet -Compatibility Win8 -MultipleInstances IgnoreNew
    $CheckPSWUTask = Get-ScheduledTask "PSWindowsUpdate" -ErrorAction SilentlyContinue

    # Check if PSWindowsUpdate Task Already exists before creating it
    if(!($CheckPSWUTask)){
        # Register Scheduled Task
        Write-Host "Registering PSWU Scheduled Task on $env:COMPUTERNAME . . .`n" -ForegroundColor Yellow
        Register-ScheduledTask -TaskName "PSWindowsUpdate" `
                            -TaskPath "\Ahikko" `
                            -Action $PSWUSchTaskAction `
                            -Trigger $PSWUSchTaskTrigger `
                            -Principal $PSWUSchTaskPrincipal `
                            -Settings $PSWUSchTaskSetting
                            
    }elseif($CheckPSWUTask.TaskPath -notlike "*Ahikko*"){
        Write-Host "Removing Existing PSWU Task first if outside of Ahikko task folder on $env:COMPUTERNAME . . .`n" -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName "PSWindowsUpdate" -Confirm:$false

        Write-Host "Registering PSWU Scheduled Task on $env:COMPUTERNAME . . .`n" -ForegroundColor Yellow
        Register-ScheduledTask -TaskName "PSWindowsUpdate" `
                            -TaskPath "\Ahikko" `
                            -Action $PSWUSchTaskAction `
                            -Trigger $PSWUSchTaskTrigger `
                            -Principal $PSWUSchTaskPrincipal `
                            -Settings $PSWUSchTaskSetting
    }elseif($CheckPSWUTask.TaskPath -like "*Ahikko*"){
        Write-Host "Looks like PSWU already exists inside Ahikko task folder on $env:COMPUTERNAME, will set task to PSWU Defaults. . .`n" -ForegroundColor Yellow
        Set-ScheduledTask -TaskName "PSWindowsUpdate" `
                          -TaskPath "\Ahikko" `
                          -Action $PSWUSchTaskAction `
                          -Trigger $PSWUSchTaskTrigger `
                          -Principal $PSWUSchTaskPrincipal `
                          -Settings $PSWUSchTaskSetting `
    }

    # Kick Start Scheduled Task
    Write-Host "Starting PSWindowsUpdate Scheduled Task . . .`n" -ForegroundColor Yellow
    Start-ScheduledTask -TaskName "PSWindowsUpdate" -TaskPath "\Ahikko"

    # Periodically check on the status of PSWindowsUpdate Scheduled Task
    $WUScheduledTaskRunStatus = (Get-ScheduledTask -TaskName "PSWindowsUpdate").State
    while($WUScheduledTaskRunStatus -like "Running"){
        $datequery = Get-Date -Format yyyy-MM-dd-hh-mm-ss
        Write-Host "Windows Update Task is currently running on $env:COMPUTERNAME as of $datequery. . ." -ForegroundColor Yellow
        Start-Sleep 60
        $WUScheduledTaskRunStatus = (Get-ScheduledTask -TaskName "PSWindowsUpdate").State
    }
    Write-Host "Windows Updates appears to have been completed on $env:COMPUTERNAME at $datequery. . ." -ForegroundColor Green

    # If AutoReboot flag is present, restart the target host
    if($Using:AutoReboot.IsPresent){
        $rebootstatus = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
            if($rebootstatus){
                Write-Host "$ENV:COMPUTERNAME is pending reboot from Windows Updates, Restarting . . ." -ForegroundColor Yellow
                shutdown /r /t 15 /c "$ENV:COMPUTERNAME pending reboot after Windows Updates, rebooting in 15 seconds . . ."
            }
    }else{
        Write-Host "Remember to manually reboot $ENV:COMPUTERNAME!!!" -ForegroundColor Yellow
    }

}
