# PocketPi Network Analyzer

Este repositorio contiene un script en Python que muestra información de la red
mediante una interfaz gráfica basada en Tkinter. Ahora la aplicación permite
seleccionar la interfaz de red y realizar escaneos ARP y de puertos para
diagnosticar la conectividad del entorno, inspirado en las funciones del
PocketEthernet.

## Archivos

- `main.py`: aplicación principal. Muestra IP, gateway, DNS, velocidad de
  enlace, VLAN detectada y estado PoE. Permite escanear la red y los puertos de
  los hosts encontrados mediante `nmap`.
- `install.sh`: script para instalar las dependencias necesarias en Raspberry Pi OS o sistemas basados en Debian.

## Uso

1. Ejecuta `./install.sh` para instalar Python y todas las dependencias
   necesarias (incluye `nmap` y `arp-scan`).
2. Inicia la interfaz con:
   ```bash
   sudo python3 main.py
   ```
   Se recomienda ejecutar como superusuario para el escaneo de red.
