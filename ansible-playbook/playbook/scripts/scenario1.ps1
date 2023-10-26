param (
	[Parameter(Mandatory=$true)]
	[System.String]
        $DomainName,
        [System.String]
        $FirstName,
        [System.String]
        $LastName,
        [System.String]
        $Password
)

# Setup Password policy
Set-ADDefaultDomainPasswordPolicy -Identity $DomainName -LockoutDuration 00:01:00 -LockoutObservationWindow 00:01:00 -ComplexityEnabled $false -ReversibleEncryptionEnabled $False -MinPasswordLength 4

# User creation
$fullname = "{0} {1}" -f ($FirstName , $LastName);
$SamAccountName = ("{0}.{1}" -f ($FirstName, $LastName)).ToLower();
$principalname = "{0}.{1}" -f ($FirstName, $LastName);
Try { New-ADUser -Name "$FirstName $LastName" -GivenName $FirstName -Surname $LastName -SamAccountName $SamAccountName -UserPrincipalName $principalname@$DomainName -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -PassThru | Enable-ADAccount } Catch {}

# Add the new User to special groups: Domain Admins + Remote Desktop Users
Add-ADGroupMember -Identity "Domain Admins" -Members $SamAccountName
Add-ADGroupMember -Identity "Remote Desktop Users" -Members $SamAccountName
