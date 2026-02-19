
# Destination
$TargetOU = "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"

$UserList = Import-Csv "users.csv"

foreach ($User in $UserList) {
    $FullName = "$($User.FirstName) $($User.LastName)"
    
    $Password = ConvertTo-SecureString "Welcome123!" -AsPlainText -Force

    Write-Host "Creating user: $FullName..." -ForegroundColor Cyan

    # Create the user in AD
    New-ADUser -Name $FullName `
               -GivenName $User.FirstName `
               -Surname $User.LastName `
               -SamAccountName $User.Alias `
               -UserPrincipalName "$($User.Alias)@inlanefreight.local" `
               -EmailAddress $User.Email `
               -Path $TargetOU `
               -AccountPassword $Password `
               -Enabled $true `
               -ChangePasswordAtLogon $true
}

Write-Host "All users created successfully!" -ForegroundColor Green
