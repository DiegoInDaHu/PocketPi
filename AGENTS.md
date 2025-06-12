# Guia del repositorio PocketPi

Este proyecto esta disenado para funcionar en **Raspbian** (Raspberry Pi OS).
Para que la aplicacion funcione correctamente es necesario ejecutar
`install.sh`, que instala todas las dependencias del sistema y las bibliotecas
de Python.

## Descripcion de archivos

- `README.md`: explica el objetivo de la aplicacion y como ejecutarla.
- `install.sh`: script de instalacion. Debe ejecutarse con `bash install.sh`
  para preparar el entorno en Raspbian.
- `main.py`: implementacion en Python y Tkinter del analizador de red
  con funciones de escaneo y configuracion de interfaces.

## Instrucciones para colaboradores

1. Tras modificar `main.py` o el script de instalacion, ejecuta
   `python3 -m py_compile main.py` para comprobar que no existen errores de
   sintaxis.
2. Si se anaden nuevas dependencias, actualiza `install.sh` y documenta los
   cambios en `README.md`.
3. Para probar la aplicacion en Raspbian, ejecuta `bash install.sh` y luego
   `sudo python3 main.py`.
