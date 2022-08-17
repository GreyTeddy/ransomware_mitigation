# powershell
pushd 'C:\Program Files\Oracle\VirtualBox'
.\VBoxManage.exe controlvm "win10.windomain.local" poweroff
.\VBoxManage.exe snapshot "win10.windomain.local" restore "Ready With Ghidra"
.\VBoxManage.exe startvm "win10.windomain.local"
echo "done"
popd