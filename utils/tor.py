"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP relacionada con la red Tor.
"""


# Módulos necesarios
import requests         # Realizar peticiones HTTP


def in_tor_network(ip) -> bool:
    """
    Verifica si una IP pertenece a la red TOR.
    
    :param ip:  Dirección IP a verificar
    
    :return:    True si pertenece a la red TOR;
                False en caso contrario
    """
    response = requests.get(f'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={ip}')

    return ip in response.text


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\033[1mTOR\033[0m\n')  # Negrita

    if in_tor_network(ip):
        print(f"La IP '{ip}' pertenece a la red Tor.")

    else:
        print(f"La IP '{ip}' no pertenece a la red Tor.")
