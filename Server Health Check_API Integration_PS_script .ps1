#*****************Dynamic entry of host to list.txt****created by Mayank Tripathi(24/07/2020)

cd\
#Invoke-Command -ComputerName 'localhost' -ScriptBlock{cmd /c bhosts -w SPB_WIN_ALL | grep -v "HOST" | grep -v "spb2k864svr2" | grep -v "noi-spbtest04" | grep -v "pc-lnipv06"| cut -d" " -f1} | Write-Output | Out-File C:\HealthCheck\list.txt
#Invoke-Command -ComputerName 'localhost' -ScriptBlock{cmd /c bhosts -w vmware_poc_all |grep -v "HOST"| cut -d" " -f1} | Write-Output | Out-File C:\HealthCheck\test\list.txt
cd\
cd C:\HealthCheck\test
$allinfo = @()
# -------------------------- Enter PCS Password one time--------------
#Password can't transfer and need to enter first time, password will save in *-PCS.txt file and can capture from next Time after comment.

#read-host "Enter PCS Password" -assecurestring | convertfrom-securestring | out-file .\username-password-PCS.txt
$username = "Global\PCS"
$password = cat .\username-password-PCS.txt | convertto-securestring
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password

function Get-HostToIP($computername) 
    {     
    $result = [system.Net.Dns]::GetHostByName($computername)     
    $result.AddressList | ForEach-Object {$_.IPAddressToString }
    }
$StartTime = (get-date).ToString('T')
Get-Content .\list.txt | %{
$computername  = $_
$record = "" | select "Name","CurrentTime","TimeZone","Online","FarmStatus", "Utility", "Release", "API", "Caption","Version","BuildNumber","OSArchitecture","LastBootUpTime","LocalDateTime","SBD","RES","LIM","Ddrivefreespace","UACStatus","Firewall","P4Login","DisplayPath","DisplayIP","PingIP","P4user","BASH_ENV","PVTS_CM","cygwin","Perl_Site","Perl_bin","LSF10_lib","LSF10_bin","PSTools","PowerShell","Perforce","J_Drive","L_Drive","N_Drive","S_Drive","U_Drive","Y_Drive"
$record.Name = $computername
#$Timezone = Get-WmiObject -Class win32_timezone -ComputerName $computername | Select-Object -Property Caption  -ErrorAction Stop
#$record.TimeZone = $Timezone
$currenttime = Get-Date -Format "h:mm:ss tt zzz"
$record.CurrentTime =$currenttime
Write-Host $computername -Foregroundcolor Yellow

#*****************Timezone capture****created by Mayank Tripathi***********
try
        {
            $Timezone = Get-WMIObject -class Win32_TimeZone -ComputerName $computername

            #$fd = Get-Date -Format "h:mm:ss tt zzz"
            if ($Timezone -like "*India Standard Time*")
            {
                foreach ($item in $Timezone)
                {
                    $record.Timezone = $Timezone.Caption
                 }
            }
            else
            {
                #Write-Host "Timezone is set to $Timezone`nTime and Date is $currenttime `n**********************`n"
                $record.Timezone = $Timezone
                badmin hclose -C "By Health Check Automated script - Time Zone mismatch" $computername
                $record.FarmStatus = Write-Output "Closed"
            }
         }
         catch
         {}  
 
if (Test-Connection $_ -Quiet -Count 2)
{ 
     $record.Online = $true

#*****************Jobname, Release and API ****created by Mayank Tripathi***********Implementation Date 28/7/2020

     try{
            
            $jobname = Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{cmd /c 'bjobs' -u PCS -w | awk '{ print $7}' | cut -d_ -f3 | cut -d. -f1 | sed -n '2 p'}
            
            $record.Release = Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{cmd /c 'bjobs' -u PCS -w | grep -v mon | awk '{ print $7}'| sed -n '2 p'}
            
            $record.API = Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{cmd /c 'bjobs' -u PCS -w -r | grep -v mon | awk '{print $7}' | sort -u | grep -v JOB |sed -n '1 p'}
            
            $Dfarm = "D:\farm_area\"
            $test = "\test\test\sync_done"
            $Utility = Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{Test-Path -Path '$Dfarm$jobname$test' -IsValid}
            
            if ($Utility -eq "True")
            {            
             #$record.Utility =  Write-Output "Matched for $jobname"
             Write-Host "Matched for $jobname" -ForegroundColor Green
             #$record.Utility = Matched for $jobname
             
             if ($Utility -like "false")
              {              
              else 
              {
              #badmin hclose -C "By Health Check Automated script - Utilies file not matched" $computername
              $record.Utility =  Write-Output "Utility Not Found"
              $record.FarmStatus = Write-Output " closed "
              }
              }
             }
             
          else
            {
             Write-Host "Utility Not Found"  -Foregroundcolor Red
             $record.Utility = Write-Output "Utility Not Found"
            }
           $record.Utility = Write-Output "Matched for $jobname"
          }
        catch {}


        try
            {
            $osinfo = gwmi -Class win32_operatingsystem -ComputerName $computername -Credential $cred -ErrorAction Stop
            $osinfo | Select-Object -Property LocalDateTime
            $record.Caption = $osinfo.Caption
            $record.Version = $osinfo.Version
            $record.BuildNumber = $osinfo.BuildNumber
            $record.OSArchitecture = $osinfo.OSArchitecture
            $record.LastBootUpTime = $osinfo.ConvertToDateTime($osinfo.LastBootUpTime)
            $record.LocalDateTime = $osinfo.ConvertToDateTime($osinfo.LocalDateTime)


        }
        catch {}

        try{

            $serviceinfo = gwmi win32_service -Filter "name='SBD'" -ComputerName $computername -Credential $cred -ErrorAction Stop
            $record.SBD = $serviceinfo.State
           <# if ($serviceinfo.State -eq 'Running')
                 {
                    
                   $record.SBD = $serviceinfo.State
                 }
                 else
                 {
                   badmin hclose -C "By Health Check Automated script - SBD Service" $computername
                   $record.FarmStatus = Write-Output "Closed"
                 }  #>
       
        }
        catch  {    }
    
        try{

            $serviceinfo = gwmi win32_service -Filter "name='RES'" -ComputerName $computername -Credential $cred -ErrorAction Stop
            $record.RES = $serviceinfo.State
           <# if ($serviceinfo.State -eq 'Running')
                 {
                    
                   $record.RES = $serviceinfo.State
                 }
                 else
                 {
                   badmin hclose -C "By Health Check Automated script  - RES Service" $computername
                   $record.FarmStatus = Write-Output "Closed"
                 }#>
        }
        catch    {    }
    
        try{

            $serviceinfo = gwmi win32_service -Filter "name='LIM'" -ComputerName $computername -Credential $cred -ErrorAction Stop
            $record.LIM = $serviceinfo.State
            <#if ($serviceinfo.State -eq 'Running')
                 {
                    
                   $record.LIM = $serviceinfo.State
                 }
                 else
                 {
                   badmin hclose -C "By Health Check Automated script  - LIM Service" $computername
                   $record.FarmStatus = Write-Output "Closed"
                 } #>
            
        }
        catch    {    }

#---------------------------------------- D drive --------------------------------------------------------------------------------------------------------

        try
            {
            
            $Ddrive = Get-CimInstance -Class CIM_LogicalDisk -ComputerName $computername | Select-Object @{Name="Free Space(GB)";Expression={[math]::round($_.freespace/1gb)}}, @{Name="Free";Expression={"{0,6:P0}" -f(($_.freespace/1gb) / ($_.size/1gb))}},DeviceID | Where-Object DeviceID -CMatch D -ErrorAction Stop
            $record.Ddrivefreespace = $Ddrive.Free
            
            }

        catch {}

#------------------------------------------------------------------------------------------------------------------------------------------------------------
try

{
$driveinfo=get-wmiobject win32_volume -ComputerName $computername | where { $_.driveletter -eq 'D:' } | select-object Freespace, capacity,driveletter

# 95 percent cutoff space
$Percent=.2

# 95% of maximum space is our warning level
$WarningLevel=$driveinfo.capacity *  $Percent

if ($driveinfo.Freespace -lt $WarningLevel)
{

send-mailmessage -from "Noida SPB Health Check <noreply@abcc.com>" -to "xyz@abcc.abcc" -subject "The D drive free space is below 95%" -body "The d drive free space is full on $computername. It is runing with $driveinfo.Freespace in bytes" -priority High -dno onSuccess, onFailure -smtpServer mailin
badmin hclose -C "By Health Check Automated script  - D Drive space full" $computername
$record.FarmStatus = Write-Output "Closed"

}

else
{

}
}
catch {}

#1.---------------------------------------- UAC STATUS ----------------------------------------------------
    try{ 
    
        $UAC = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA }).enableLUA 
                if ($uac -eq '1')
                 {
                   # Write-Host "UAC Enabled"  -Foregroundcolor Red
                    $record.UACStatus =  Write-Output "Enabled"
                    badmin hclose -C "By Health Check Automated script - UAC Enabled" $computername
                    $record.FarmStatus = Write-Output "Closed"
                 }
                 else
                 {
                    $record.UACStatus =  Write-Output "Disabled"
                 }
        }   catch{}
#2. -------------------- Firewall STATUS ------------
try{ 
           $Firewall = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile -Name EnableFirewall}).enablefirewall
             if ($Firewall -eq '1')
                 {
                    
                   # Write-Host "Firewall Enabled"  -Foregroundcolor Red
                    $record.Firewall =  Write-Output "Enabled"
                    badmin hclose -C "By Health Check Automated script - Firewall Enabled" $computername
                    $record.FarmStatus = Write-Output "Closed"
                 }
                 else
                 {
                   $record.Firewall =  Write-Output "Disabled"
                 }
        }   catch{}

#3. ----------- P4 Login Status with expiry time --------------
        try
          { 
          $record.P4Login = Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{cmd /c 'p4.exe' login -s} -ErrorAction Stop     
                 
          }   catch {$record.P4Login =  Write-Output "Not found"}

#4. -------------- DISPLAY Env Path check ------------------
           try{
                $record.DisplayIP = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name DISPLAY)}).DISPLAY
                $record.PingIP = Get-HostToIP($_)
                if ($record.DisplayIP -eq $record.PingIP)
                 {
                    $record.DisplayPath =  Write-Output "Match"
                 }
                 else
                 {
                    # Write-Host "DISPLAY Path IP MIS-Matched"  -Foregroundcolor Red
                     $record.DisplayPath =  Write-Output "Mis-Match"
                     badmin hclose -C "By Health Check Automated script - Display Env Mis-match" $computername
                     $record.FarmStatus = Write-Output "Closed"
                 }
        } catch {badmin hclose -C "By Health Check Automated script - Display Env not found" $computername
                 $record.FarmStatus = Write-Output "Closed"
                }

#5. ------------- P4User Env Path check ----------
            try{
                $record.P4User = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name P4USER)} -ErrorAction Stop).P4USER
                if ($record.P4User -eq 'PCS')
                 {
                    $record.P4User =  Write-Output "Yes"
                 }
                 else
                 {
                     $record.P4User =  Write-Output "No"
                     badmin hclose -C "By Health Check Automated script - PCS Env not found" $computername
                     $record.FarmStatus = Write-Output "Closed"
                 }
        } catch {$record.P4User =  Write-Output "No"
                   badmin hclose -C "By Health Check Automated script - PCS Env not found" $computername
                    $record.FarmStatus = Write-Output "Closed"
                 }


#6. -------------- BASH_ENV Env Path check ------------------
           try{
                $record.BASH_ENV = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Environment' -Name BASH_ENV)} -ErrorAction Stop).BASH_ENV
                if ($record.BASH_ENV -eq 'C:\cygwin\home\PCS\cadence_cygwin_profile')
                 {
                    $record.BASH_ENV =  Write-Output "Yes"
                 }
                 else
                 {
                   #  Write-Host "BASH_ENV Env not found"  -Foregroundcolor Red
                     $record.BASH_ENV =  Write-Output "No"
                     badmin hclose -C "By Health Check Automated script - Bash_Env not found" $computername
                     $record.FarmStatus = Write-Output "Closed"
                 }
        } catch {$record.BASH_ENV =  Write-Output "No"
                 badmin hclose -C "By Health Check Automated script - Bash_Env not found" $computername
                 $record.FarmStatus = Write-Output "Closed"
                 }
#7. -------------- .Path Env Path check ------------------
            try{
                $PathVars = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name Path )}).Path -split ';'|fl | Format-Table -AutoSize -Wrap
#Array Length PS------ Write-Host $PathVars.Length
                $PathVars | % { $_ } | Out-File .\Path.txt

#7.1 -------------- #PVTS_CM path ------------------
                    $PVTSSEL = Select-String -Path ".\Path.txt" -Pattern "U:\pvts_CM\bin.wint\software\perl\bin" -SimpleMatch
                      if ($PVTSSEL -ne $null)
                        {
                            $record.PVTS_CM =  Write-Output "Yes"
                        }
                        else
                        {
                           # Write-Host "PVTS_CM not found"  -Foregroundcolor Red
                            $record.PVTS_CM =  Write-Output "No"
                            #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                            badmin hclose -C "By Health Check Automated script - PVTS_CM not found" $computername 
                            $record.FarmStatus = Write-Output "Closed"
                        }
            
#7.2 -------------- cygwin path ------------------
            $cygwinSEL = Select-String -Path ".\Path.txt" -Pattern 'C:\cygwin\bin' -SimpleMatch
                if ($cygwinSEL -ne $null)
                {
                    $record.cygwin =  Write-Output "Yes"
                }
                else
                {
                   # Write-Host "cygwin not found"  -Foregroundcolor Red
                    $record.cygwin =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                }

#7.3 -------------- #Perl64\site path ------------------
            $Perl_SiteSEL = Select-String -Path ".\Path.txt" -Pattern 'C:\Perl64\site\bin' -SimpleMatch
              if ($Perl_SiteSEL -ne $null)
                {
                    $record.Perl_Site =  Write-Output "Yes"
                }
                else
                {
                  #  Write-Host "Perl64\site not found"  -Foregroundcolor Red
                    $record.Perl_Site =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                }

#7.4 -------------- #Perl64\bin path ------------------
            $Perl_binSEL = Select-String -Path .\Path.txt -Pattern 'C:\Perl64\bin' -SimpleMatch
              if ($Perl_binSEL -ne $null)
                {
                    $record.Perl_bin =  Write-Output "Yes"
                }
                else
                {
                   # Write-Host "Perl64\bin not found"  -Foregroundcolor Red
                    $record.Perl_bin =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                }
                      
#7.5 -------------- #LSF_10.1\10.1\bin path ------------------
            $LSF10_binSEL = Select-String -Path .\Path.txt -Pattern 'C:\LSF_10.1\10.1\bin' -SimpleMatch
              if ($LSF10_binSEL -ne $null)
                {
                    $record.LSF10_bin =  Write-Output "Yes"
                }
                else
                {
                   # Write-Host "LSF_10.1\10.1\bin not found"  -Foregroundcolor Red
                    $record.LSF10_bin =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                }
<#
#7.6 -------------- #LSF_9.1\9.1\bin path ------------------
            $LSF9_binSEL = Select-String -Path .\Path.txt -Pattern 'C:\LSF_9.1\9.1\bin' -SimpleMatch
              if ($LSF9_binSEL -ne $null)
                {
                    $record.LSF9_bin =  Write-Output "Yes"
                }
                else
                {
                   # Write-Host "LSF_9.1\9.1\bin not found"  -Foregroundcolor Red
                    $record.LSF9_bin =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                }
#>
#7.7 -------------- #LSF_10.1\10.1\lib path ------------------
            $LSF10_libSEL = Select-String -Path .\Path.txt -Pattern 'C:\LSF_10.1\10.1\lib' -SimpleMatch
              if ($LSF10_libSEL -ne $null)
                {
                    $record.LSF10_lib =  Write-Output "Yes"
                }
                else
                {
                  #  Write-Host "LSF_10.1\10.1\lib not found"  -Foregroundcolor Red
                    $record.LSF10_lib =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                }
<#
#7.8 -------------- #LSF_9.1\9.1\lib path ------------------
            $LSF9_libSEL = Select-String -Path .\Path.txt -Pattern 'C:\LSF_9.1\9.1\lib' -SimpleMatch
              if ($LSF9_libSEL -ne $null)
                {
                    $record.LSF9_lib =  Write-Output "Yes"
                }
                else
                {
                 #   Write-Host "LSF_9.1\9.1\lib not found"  -Foregroundcolor Red
                    $record.LSF9_lib =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                }
#>
#7.9 -------------- #U:\pvts_CM\bin.wint\software\pstools1.12 path ------------------
            $pstoolsSEL = Select-String -Path .\Path.txt -Pattern 'U:\pvts_CM\bin.wint\software\pstools1.12' -SimpleMatch
              if ($pstoolsSEL -ne $null)
                {
                    $record.pstools =  Write-Output "Yes"
                }
                else
                {
                 #   Write-Host "pvts_CM\bin.wint\software\pstools1.12 not found"  -Foregroundcolor Red
                    $record.pstools =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                }     
#7.10 ------------- #WindowsPowerShell\v1.0\ path ------------------
            $PshellSEL = Select-String -Path .\Path.txt -Pattern 'WindowsPowerShell\v1.0\' -SimpleMatch
              if ($PshellSEL -ne $null)
                {
                    $record.PowerShell =  Write-Output "Yes"
                }
                else
                {
                  #  Write-Host "System32\WindowsPowerShell\v1.0\ not found"  -Foregroundcolor Red
                    $record.PowerShell =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                }
<#
#7.11 -------------- #System32\Wbem ------------------
            $WbemSEL = Select-String -Path .\Path.txt -Pattern 'System32\Wbem' -SimpleMatch
              if ($wbemSEL -ne $null)
                {
                    $record.Wbem =  Write-Output "Yes"
                }
                else
                {
                  #  Write-Host "System32\WindowsPowerShell\v1.0\ not found"  -Foregroundcolor Red
                    $record.Wbem =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                }
#>
#7.12 -------------- #Program Files\Perforce ------------------
            $PerforceSEL = Select-String -Path .\Path.txt -Pattern 'Program Files\Perforce' -SimpleMatch
              if ($PerforceSEL -ne $null)
                {
                    $record.Perforce =  Write-Output "Yes"
                }
                else
                {
                  #  Write-Host "Program Files\Perforce not found"  -Foregroundcolor Red
                    $record.Perforce =  Write-Output "No"
                    #Invoke-Command -ComputerName "win10spb-1809" -ScriptBlock {$oldpath = [System.Environment]::GetEnvironmentVariable("PATH","Machine"); Write-Output $oldpath; $newpath = $oldpath+";C:\SomeTestPath"; [System.Environment]::SetEnvironmentVariable("PATH",$newpath,"Machine"); Write-Output "New Path"; [System.Environment]::GetEnvironmentVariable("PATH","Machine")  }
                    badmin hclose -C "By Health Check Automated script - Perforce Env not found" $computername
                    $record.FarmStatus = Write-Output "Closed"
                }

       } Catch {}
#8. --------------J Network Drive Check ------------------
           try{
                $record.J_Drive = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Network\J')} -ErrorAction Stop).RemotePath
                if ($record.J_Drive -eq '\\noinapb01\cmtool')
                 {
                    $record.J_Drive =  Write-Output "Found"
                 }
                 else
                 {
                    $record.J_Drive =  Write-Output "Not Found"
                    badmin hclose -C "By Health Check Automated script - Different J Drive found" $computername
                    $record.FarmStatus = Write-Output "Closed"
                 }
            } catch {$record.J_Drive =  Write-Output "Not Found"
                     badmin hclose -C "By Health Check Automated script - J Drive not found" $computername
                     $record.FarmStatus = Write-Output "Closed"}
#9. --------------L Network Drive Check ------------------
           try{
                $record.L_Drive = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Network\L')} -ErrorAction Stop).RemotePath
                if ($record.L_Drive -eq '\\noinapb01\PVTS')
                 {
                    $record.L_Drive =  Write-Output "Found"
                 }
                 else
                 {
                     $record.L_Drive =  Write-Output "Not Found"
                     badmin hclose -C "By Health Check Automated script - Different L Drive found" $computername
                     $record.FarmStatus = Write-Output "Closed"
                 }
        } catch {$record.L_Drive =  Write-Output "Not Found"
                 badmin hclose -C "By Health Check Automated script - L Drive not found" $computername 
                 $record.FarmStatus = Write-Output "Closed"}
#10. --------------N Network Drive Check ------------------
           try{
                $record.N_Drive = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Network\N')} -ErrorAction Stop).RemotePath
                if ($record.N_Drive -eq '\\noiclapa02\psd_install')
                 {
                    $record.N_Drive =  Write-Output "Found"
                 }
                 else
                 {
                     $record.N_Drive =  Write-Output "Not Found"
                     badmin hclose -C "By Health Check Automated script - Different N Drive found" $computername 
                     $record.FarmStatus = Write-Output "Closed"
                 }
        } catch {$record.N_Drive =  Write-Output "Not Found"
                 badmin hclose -C "By Health Check Automated script - N Drive not found" $computername 
                 $record.FarmStatus = Write-Output "Closed"}
#11. --------------S Network Drive Check ------------------
           try{
                $record.S_Drive = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Network\S')} -ErrorAction Stop).RemotePath
                if ($record.S_Drive -eq '\\noiclapa02\share')
                 {
                    $record.S_Drive =  Write-Output "Found"
                 }
                 else
                 {
                     $record.S_Drive =  Write-Output "Not Found"
                     badmin hclose -C "By Health Check Automated script - Different S Drive found" $computername
                     $record.FarmStatus = Write-Output "Closed"
                 }
        } catch {$record.S_Drive =  Write-Output "Not Found"
        badmin hclose -C "By Health Check Automated script - S Drive not found" $computername
        $record.FarmStatus = Write-Output "Closed" }
#12. --------------U Network Drive Check ------------------
           try{
                $record.U_Drive = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Network\U')} -ErrorAction Stop).RemotePath
                if ($record.U_Drive -eq '\\noinapb02\psdstore4')
                 {
                    $record.U_Drive =  Write-Output "Found"
                 }
                 else
                 {
                     $record.U_Drive =  Write-Output "Not Found"
                     badmin hclose -C "By Health Check Automated script - Different U Drive found" $computername
                     $record.FarmStatus = Write-Output "Closed"
                 }
        } catch {$record.U_Drive =  Write-Output "Not Found"
                 hclose -C "By Health Check Automated script - U Drive not found" $computername
                 $record.FarmStatus = Write-Output "Closed" }
#13. --------------Y Network Drive Check ------------------
           try{
                $record.Y_Drive = (Invoke-Command -ComputerName $computername -Credential $cred -ScriptBlock{(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Network\Y')} -ErrorAction Stop).RemotePath
                if ($record.Y_Drive -eq '\\noinapb01\cm\cdrom\SPB')
                 {
                    $record.Y_Drive =  Write-Output "Found"
                 }
                 else
                 {
                     $record.Y_Drive =  Write-Output "Not Found"
                     badmin hclose -C "By Health Check Automated script - Different Y Drive found" $computername
                     $record.FarmStatus = Write-Output "Closed"
                 }
        } catch {$record.Y_Drive =  Write-Output "Not Found"
                 badmin hclose -C "By Health Check Automated script - Y Drive not found" $computername
                 $record.FarmStatus = Write-Output "Closed"}
# ----------- IF Block End ----------
} else { $record.Online = $false }

#-------------------------------------------------API-----------created on (24/7/2020)-----Implemented (28/7/2020)
$url = "https://pvtools.****.com/compass/api/get-table-from-seq-list?seq="
$seq = $record.API
$record.API = Invoke-RestMethod -Uri "$url$seq" -Method Get
Write-Host "For API release :: $seq" -ForegroundColor Green
Write-Host " For Build $record.API" -ForegroundColor Green

$url = "http://noi-pvtools.****.com/compass/api/get-wint-farm-data?"
$key = "wintData="
$gk = Invoke-RestMethod -Uri "$url$key$record" -Method Get
Write-Host "Matched for $gk" -ForegroundColor Green

$allinfo += $record

}  
Remove-Item -Path .\Path.txt -Recurse -Force -ErrorAction Ignore #1.  Path File Delete
$EndTime = (get-date).ToString('T')


#*****************Output File Name Change****created by Mayank Tripathi(28/07/20202)*************************************************************************

$val1 = ".\"
$val2 = $record.Release
$val3 = "-"
$DateVal = $((Get-Date).ToString('MM-dd-yyyy_HHmm'))


$allinfo | Export-Csv $val1$val2$val3$DateVal.csv -NoTypeInformation -Force
#$allinfo | Export-Csv .\spbfarminfo$((Get-Date).ToString('MM-dd-yyyy_HHmm')).csv -NoTypeInformation -Force


#$EData = $allinfo | Format-Table Name, CurrentTime, TimeZone, Online, Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime, LocalDateTime, CurrentTimeZone, SBD, RES, LIM, D_Drive, UACStatus, Firewall, P4Login, DisplayPath, DisplayIP, PingIP, P4user, BASH_ENV, PVTS_CM, cygwin, Perl_Site, Perl_bin, LSF10_lib, LSF10_bin, LSF9_lib, LSF9_bin, PSTools, PowerShell, Wbem, Perforce, J_Drive, L_Drive, N_Drive, S_Drive, U_Drive, Y_Drive -AutoSize 
$bdy = "Hi,<br><br>"
$bdy += "Please find the attached file for Noida SPB health check report.<br>"
$bdy += "Trigger started at $StartTime and end at: $EndTime.<br><br>"
$bdy += "Regards,<br>"
$bdy += "IT Team"
$filename = "$val2$val3$DateVal.csv"
#$filename = "spbfarminfo$((Get-Date).ToString('MM-dd-yyyy_HHmm')).csv"
$Attach = ".\$filename"
#$emailto = "xyz@abcc.abcc","xyz@abcc.abcc","xyz@abcc.abcc","xyz@abcc.abcc","xyz@abcc.abcc"
$emailto = 'xyz@abcc.abcc'
#$emailto = 'xyz@abcc.abcc'
$emailfrom = 'Noida SPB Health Check <noreply@abcc.com>'
$emailCC = 'xyz@abcc.abcc'
$emailserver = 'mailin'
Send-MailMessage -To $emailto -cc $emailCC -From $emailfrom -Subject 'Noida SPB Health Check Daily' -Attachments $Attach -Body $bdy -BodyAsHtml -SmtpServer $emailserver
#Send-MailMessage -To $emailto -From $emailfrom -Subject 'SPB Health Check' -Attachments $Attach -Body ($allinfo | Out-String) -SmtpServer $emailserver 