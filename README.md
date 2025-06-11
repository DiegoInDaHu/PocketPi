# PocketPi Network Analyzer

Este repositorio contiene un script en Python que muestra información de la red
mediante una interfaz gráfica basada en Tkinter. Ahora la aplicación permite
seleccionar la interfaz de red y realizar escaneos ARP y de puertos para
diagnosticar la conectividad del entorno, inspirado en las funciones del
PocketEthernet.

## Archivos

- `main.py`: aplicación principal. Muestra IP, gateway, DNS, velocidad de
  enlace, VLAN detectada y estado PoE. Permite escanear la red y los puertos de
  los hosts encontrados mediante `nmap`. Incluye una pestaña para hacer `ping`
  a cualquier host y otra para configurar la red de la interfaz seleccionada
  (DHCP o IP estática).
- `install.sh`: script para instalar las dependencias necesarias en Raspberry Pi OS o sistemas basados en Debian (incluye `pyroute2` para detectar VLAN).

## Uso

1. Ejecuta `./install.sh` para instalar Python y todas las dependencias
   necesarias (incluye `nmap`, `arp-scan`, `iputils-ping` e `iproute2`).
2. Inicia la interfaz con:
   ```bash
   sudo python3 main.py
   ```
   Se recomienda ejecutar como superusuario para el escaneo de red.

3. En la pesta\u00f1a **Actualizaci\u00f3n** puedes comprobar si existen
   nuevas versiones del c\u00f3digo y aplicarlas autom\u00e1ticamente. El proceso
   ejecuta `git pull` e `install.sh` con `sudo` para aplicar las actualizaciones.

Recuerda que la pestaña de actualización solo funciona si ejecutas la aplicación desde un clon de Git con un remoto accesible.
