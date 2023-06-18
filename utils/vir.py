"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP relacionada con VirusTotal.
"""


# Módulos necesarios
import json             # Interpretación de ficheros JSON
import requests         # Realizar peticiones HTTP


# Variables globales
_VIRUSTOTAL_API_KEY = None


def set_api_key(key: str) -> None:
    """
    Establece la clave de la API para poder
    usar las funcionalidades de este módulo.

    :param key:     Una clave API de VirusTotal
    """
    global _VIRUSTOTAL_API_KEY

    _VIRUSTOTAL_API_KEY = key


def get_reputation(ip: str) -> str or None:
    """
    Verifica la reputación de una IP en VirusTotal.

    :param ip:  Dirección IP a verificar

    :return:    Cadena con la reputación de la IP en VirusTotal;
                None en caso contrario
    """
    response = requests.get(f'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={_VIRUSTOTAL_API_KEY}&ip={ip}')

    if response.status_code == 200:
        return json.loads(response.text)

    return None


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\033[1mVirusTotal\033[0m\n')  # Negrita

    reputation = get_reputation(ip)

    if reputation:
        print(json.dumps(reputation, indent=4))

    else:
        print(f"\033[31mNo se encontró información sobre '{ip}'.\033[0m")
