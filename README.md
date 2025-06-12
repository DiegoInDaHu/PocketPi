# PocketPi Network Analyzer

Este repositorio contiene un script en Python que muestra información de la red
mediante una interfaz gráfica basada en Tkinter. Ahora la aplicación permite
seleccionar la interfaz de red y realizar escaneos ARP y de puertos para
diagnosticar la conectividad del entorno, inspirado en las funciones del
PocketEthernet.

## Archivos

- `main.py`: aplicación principal. Muestra IP, gateway, DNS, velocidad de
  enlace, VLAN detectada, estado PoE y detecta vecinos CDP/LLDP. Permite escanear la red y los puertos de
  los hosts encontrados mediante `nmap`. Incluye una pestaña para hacer `ping`
  a cualquier host, otra de **pruebas externas** que verifica la conectividad de
  un puerto TCP y otra para configurar la red de la interfaz seleccionada. La
  IP pública aparece directamente en la pestaña principal sin necesidad de
  pulsar ningún botón
  (DHCP o IP estática). La configuración se guarda en `/etc/dhcpcd.conf` para
  que persista tras reiniciar.
- `install.sh`: script para instalar las dependencias necesarias en Raspberry Pi OS o sistemas basados en Debian (incluye `pyroute2` para detectar VLAN).

## Uso

1. Ejecuta `./install.sh` para instalar Python y todas las dependencias
   necesarias (incluye `nmap`, `arp-scan`, `iputils-ping` e `iproute2`). El
   script también instala las bibliotecas de Python `netifaces`, `psutil`,
   `scapy`, `python-nmap` y `pyroute2`.
2. Inicia la interfaz con:
   ```bash
   sudo python3 main.py
   ```
   Se recomienda ejecutar como superusuario para el escaneo de red.

3. Al iniciar la aplicación se comprueba si existen nuevas versiones del código. Si hay una actualización disponible aparecerá un cuadro de diálogo que permite instalarla o cancelarla. El proceso ejecuta `git pull --ff-only` e `install.sh` con `sudo` para aplicar las actualizaciones sin crear commits de fusión.

Recuerda que la comprobación de actualizaciones solo funciona si ejecutas la aplicación desde un clon de Git con un remoto accesible.
