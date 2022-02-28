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

1. Método Reflection de Matt Graeber
2. Error Forzado
3. DLL Hijacking
4. Memory Patching
5. Ofuscación con Chimera


[Método Reflection de Matt Graeber](#reflection)
