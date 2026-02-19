This section contains ps commands that are useful to someone starting with AD
I also made a script to add users to a security group based on csv file.

Every command could be found in ms [learn doc](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)

### Basic user Identity management

#### Add OU 
```
New-ADOrganizationalUnit -Name "Security Analysts" -Path "OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```

#### Identity Management (Users & Groups)

#### Add group

```
New-ADGroup -Name "Security_Analyst_Admins" -GroupCategory Security -GroupScope Global -Path ...
```

#### Add user


```
$Password = ConvertTo-SecureString "P@ssword123!" -AsPlainText -Force

New-ADUser -Name "John Doe" `
           -SamAccountName "jdoe" `
           -UserPrincipalName "jdoe@inlanefreight.local" `
           -AccountPassword $Password `
           -Enabled $true `
           -ChangePasswordAtLogon $true `
           -Path "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```

#### Add user to group
```
Add-ADGroupMember -Identity "Security_Analyst_Admins" -Members "jdoe"
```

#### Password reset

```
$NewPass = ConvertTo-SecureString "NewTempPass123!" -AsPlainText -Force
Set-ADAccountPassword -Identity "jdoe" -NewPassword $NewPass -Reset
```
The user may have failed to login several times and is thus locked out, this will solve it
```
Unlock-ADAccount -Identity "jdoe"
```


#### Delete user

```
Remove-ADUser -Identity "jdoe" -Confirm:$false
```

### Endpoint Management (Joining & Moving)

Adding a Workstation to join the Domain => will prompt password
```
Add-Computer -DomainName "BUSINESS.LOCAL" -Credential "BUSINESS\business-admin" -Restart
```

Run this on the DC to move the computer to its correct OU
```
Move-ADObject -Identity "CN=ACADEMY-IAD-W10,CN=Computers,DC=BUSINESS,DC=LOCAL" `
              -TargetPath "OU=Workstations,OU=Computers,OU=Corp,DC=BUSINESS,DC=LOCAL"
```

### GPO management
duplicating a GPO

```
Copy-GPO -SourceGpoName "Logon Banner" -TargetGpoName "Security Analysts Control"
````
linking a gpo to a target

```
New-GPLink -Name "Security Analysts Control" -Target "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```


The rest is done within the  Group Policy Management (GPMC) interface, edit the rule and have fun, change password criteria to further harden the AD and its users

```# Link the 'Security Analysts Control' GPO to the 'Security Analysts' OU
Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy
```



