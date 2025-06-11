# PocketPi Network Analyzer

Este repositorio contiene un script en Python que muestra información de la red mediante una interfaz gráfica basada en Tkinter.

## Archivos

- `main.py`: aplicación principal. Muestra IP, gateway, DNS, velocidad de enlace, VLAN detectada, estado PoE y permite escanear la red.
- `install.sh`: script para instalar las dependencias necesarias en Raspberry Pi OS o sistemas basados en Debian.

## Uso

1. Ejecuta `./install.sh` para instalar Python y las bibliotecas requeridas.
2. Inicia la interfaz con:
   ```bash
   sudo python3 main.py
   ```
   Se recomienda ejecutar como superusuario para el escaneo de red.
