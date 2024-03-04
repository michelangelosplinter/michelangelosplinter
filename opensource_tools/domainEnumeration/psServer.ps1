
# Fuck you N***a
param(
  [string]$username,
  [string]$password
)

# Converting credentials to secure string
$SecureString = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential( $username, $SecureString )

# Creating a background thread
$job = Start-Job -Credential $credential -ScriptBlock {

  # executed commands
  Get-localuser | select-Object -Property Name, fullname, sid, description, lastlogon | ConvertTo-Json -depth 1  > "C:\Users\mador\OneDrive\Desktop\Michael\Domain_Enum\1.json";
  Get-localgroup | select-Object -Property Name, fullname, sid, description, lastlogon | ConvertTo-Json -depth 1  > "C:\Users\mador\OneDrive\Desktop\Michael\Domain_Enum\2.json";
}

# Waiting for the Job to finish
Wait-Job -ID $job.Id
