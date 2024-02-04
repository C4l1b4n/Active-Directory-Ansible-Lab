$restart_group = "ServiceManagers"
$path = "C:\Users\Administrator\Desktop\WiseCare365.exe"


# Install Wise Care
& $path /VERYSILENT /DIR="C:\apps\Wise\Wise Care 365\"

# Wait for installation
Start-Sleep -Seconds 30

# Setup auto-delayes restart
sc.exe config WiseBootAssistant start= delayed-auto

# Create "restart service" group
net localgroup /add $restart_group

# Remove WiseCare's generated shortcuts
rm C:\Users\Public\Desktop\*.lnk

# Get restart_group SID
$sid = (Get-Localgroup $restart_group).SID

# Inject permissions
$perm = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RPWPDTRC;;;$sid)"
sc.exe sdset WiseBootAssistant $perm
