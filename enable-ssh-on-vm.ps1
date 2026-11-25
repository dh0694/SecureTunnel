# Run this on the Windows VM (NOT this PC), in PowerShell as Administrator:
#   Start > type PowerShell > right-click "Windows PowerShell" > Run as administrator
# Then paste everything below and press Enter. The first line takes a minute or two.
# When it finishes, send Claude the last two lines it prints (IPv4 address and username).

Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service sshd -StartupType Automatic
Set-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINsGjfDIiT2wIj16isfQo61XLX3YI82ZmtBgpx60m9o2 cbutler_dom\dhiggins@CB15432'
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -PropertyType String -Force
ipconfig | findstr IPv4
whoami
