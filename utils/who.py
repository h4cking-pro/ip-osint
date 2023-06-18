"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP obtenida con el comando 'whois'.
"""


# Módulos necesarios
import os               # Ejecución de comandos del sistema


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\033[1mwhois\033[0m\n')  # Negrita

    print(os.system(f'whois {ip}'))
