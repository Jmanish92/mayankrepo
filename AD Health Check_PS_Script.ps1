#*****************AD HealthCheck and replication summary result****created by Mayank Tripathi(25/12/2021)
repadmin /replsum | Out-File -FilePath C:\Users\Administrator\Documents\healthcheckscript\replication-summary.txt
Out-File -FilePath C:\Users\Administrator\Documents\healthcheckscript\replication-summary.txt -Append -InputObject "---------------------C DRIVE STATUS---------------------" -Width 100
$allinfo = @()
$StartTime = (get-date).ToString('T')

$getForest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
$DCServers = @($getForest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} )
$DCServers

foreach ($DC in $DCServers){
$DC | Out-File -FilePath C:\Users\Administrator\Documents\healthcheckscript\replication-summary.txt -Append
$d = @(Invoke-Command -ComputerName $DC {Get-PSDrive | Where {$_.Free -gt 0}})| Out-File -FilePath C:\Users\Administrator\Documents\healthcheckscript\replication-summary.txt -Append
}

Out-File -FilePath C:\Users\Administrator\Documents\healthcheckscript\replication-summary.txt -Append -InputObject "---------------------Replication verification---------------------" -Width 100
DCDIAG /test:CheckSecurityError | Out-File -FilePath C:\Users\Administrator\Documents\healthcheckscript\replication-summary.txt -Append

$body = netdom trust nda1f1r1.com /Domain:nda1f2r1.com /twoway /Verify /verbose /UserO:Administrator /PasswordO:******* /UserD:Administrator /PasswordD:*******
#$body

$EndTime =(get-date).ToString('T')

#SMTP code for mail alert 

$fromaddress = "noreply@abcc.in"
$toaddress = "xyz@abcc.abcc,xyz@abcc.abcc"
$Subject = "PAS ENV1 Replication Summary Result"
$bdy = "Hi,<br><br>"
$bdy += "Please find the attached Replication summary result for PAS Environment 1.<br>"
$bdy += "Trigger started at $StartTime and end time at: $EndTime.<br><br>"
$bdy += "Regards,<br>"
$bdy += "IT Team"
$filename = "C:\Users\Administrator\Documents\healthcheckscript\replication-summary.txt"
$attachment = "$filename"
$smtpserver = "xxx.xxx.xx.xx"
$message = new-object System.Net.Mail.MailMessage
$message.From = $fromaddress
$message.To.Add($toaddress)
$message.IsBodyHtml = $True
$message.Subject = $Subject
$attach = new-object Net.Mail.Attachment($attachment)
$message.Attachments.Add($attach)
$message.body = $bdy
$smtp = new-object Net.Mail.SmtpClient($smtpserver)
$smtp.Send($message)