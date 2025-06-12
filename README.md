# PocketPi Network Analyzer

Este repositorio contiene un script en Python que muestra información de la red
mediante una interfaz gráfica basada en Tkinter. Ahora la aplicación permite
seleccionar la interfaz de red y realizar escaneos ARP y de puertos para
diagnosticar la conectividad del entorno, inspirado en las funciones del
PocketEthernet.

La interfaz se ha rediseñado con botones y textos más grandes para su uso en
pantallas táctiles.

## Archivos

- `main.py`: aplicación principal. Muestra IP, gateway, DNS, velocidad de
  enlace, VLAN detectada, estado PoE y detecta vecinos CDP/LLDP. Permite escanear la red y los puertos de
- los hosts encontrados mediante `nmap`. Incluye una pestaña para hacer `ping`
  a cualquier host, otra de **pruebas externas** que verifica la conectividad de
  un puerto TCP, otra para **port blinker** que parpadea el puerto mediante
  `ethtool` y otra para configurar la red de la interfaz seleccionada. La
  IP pública aparece directamente en la pestaña principal sin necesidad de
  pulsar ningún botón
  (DHCP o IP estática). La configuración se guarda en `/etc/dhcpcd.conf` para
  que persista tras reiniciar.
  Además, las pestañas de escaneo y ping permiten introducir un ID de VLAN.
  Si se especifica, las pruebas se realizan usando la interfaz etiquetada
  correspondiente (por ejemplo `eth0.10`).
  Las VLAN temporales creadas para estas pruebas se eliminan automáticamente
  al iniciar la aplicación para evitar que queden interfaces residuales.
- `install.sh`: script para instalar las dependencias necesarias en Raspberry Pi OS o sistemas basados en Debian. Emplea el Python obtenido con `which python3` para que las bibliotecas funcionen al ejecutar la aplicación con privilegios (incluye `pyroute2` para detectar VLAN y `ethtool` para el parpadeo de puertos).

## Uso

1. Ejecuta `./install.sh` para instalar Python y todas las dependencias
   necesarias (incluye `nmap`, `arp-scan`, `iputils-ping`, `iproute2` y
   `ethtool`). El
   script también instala las bibliotecas de Python `netifaces`, `psutil`,
   `scapy`, `python-nmap` y `pyroute2`. El instalador detecta si `pip` admite
   la opción `--break-system-packages` y la usa solo cuando está disponible,
   garantizando compatibilidad con versiones antiguas de la herramienta.
2. Inicia la interfaz con:
   ```bash
   sudo $(which python3) main.py
   ```
   Se recomienda ejecutar como superusuario para el escaneo de red. Si no se dispone de un entorno gráfico, el programa finalizará mostrando un mensaje de error.

3. Al iniciar la aplicación se comprueba si existen nuevas versiones del código. Si hay una actualización disponible aparecerá un cuadro de diálogo que permite instalarla o cancelarla. El proceso ejecuta `git pull --ff-only` e `install.sh` con `sudo` para aplicar las actualizaciones sin crear commits de fusión.

Recuerda que la comprobación de actualizaciones solo funciona si ejecutas la aplicación desde un clon de Git con un remoto accesible.
