# Project 005: validated local lab comparison using real Security Event 4698 records.
# Shows both lab tasks and whether the three-indicator rule matches.
# Use an elevated PowerShell session.
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698;StartTime=(Get-Date).AddDays(-7)} | Where-Object {$_.Message -match 'DetectionResearch005-(AuditTest|PowerShellLogon)'} | Select-Object TimeCreated,@{Name='TaskName';Expression={([regex]::Match($_.Message,'Task Name:\s*(\\DetectionResearch005-[^\r\n]+)')).Groups[1].Value}},@{Name='Alert';Expression={($_.Message -match '(?i)<Command>\s*(?:[^<]*\\)?(?:powershell|pwsh)(?:\.exe)?\s*</Command>') -and ($_.Message -match '(?is)<Arguments>[^<]*\\AppData\\[^<]*\.ps1') -and ($_.Message -match '<LogonTrigger>')}} | Format-Table -AutoSize
