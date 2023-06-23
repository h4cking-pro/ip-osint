"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP relacionada con VirusTotal.
"""


# Módulos necesarios
import json                 # Interpretación de ficheros JSON
import requests             # Realizar peticiones HTTP

from io import StringIO     # Lectura de ficheros


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
    response = requests.get(f'https://www.virustotal.com/vtapi/v2/ip-address'
                            f'/report?apikey={_VIRUSTOTAL_API_KEY}&ip={ip}')

    if response.status_code == 200:
        data = json.loads(response.text)
        return data if data['response_code'] == 1 else None     # 1: respuesta correcta

    return None


def _get_country(country_code: str) -> str:
    """
    Obtiene el nombre del país a partir de su código.

    :param country_code:    Código del país

    :return:                Nombre del país
    """
    try:
        response = requests.get(f'https://restcountries.com/v3.1/alpha/{country_code}')

        if response.status_code == 200:
            data = response.json()[0]

            # Comprobar si existe traducción en español ('spa')
            if 'spa' in data['translations']:
                return data['translations']['spa']['common']

            elif 'name' in data:
                return data['name']['common']

            else:
                return '\033[31mdesconocido\033[0m'
        else:
            return '\033[31mmno encontrado\033[0m'

    except requests.exceptions.RequestException:
        return '\033[31mmno encontrado\033[0m'


def _print_singles(reputation: dict):
    """
    Muestra la información de la IP que no requiere de un formato especial.

    :param reputation:  Diccionario con la información de la IP
    """
    msg = StringIO()
    country = _get_country(reputation['country'])

    # Construir el mensaje
    msg.write(f'Sistema Autónomo (AS): {reputation["as_owner"]} ({reputation["asn"]}).\n')
    msg.write(f'Perteneciente a \'{country}\' ({reputation["country"]}).\n')

    # Mostrar el mensaje
    print(msg.getvalue())

    msg.close()             # Debe cerrarse el buffer una vez se haya usado


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\033[1mVirusTotal\033[0m\n')  # Negrita

    reputation = get_reputation(ip)

    if reputation:
        _print_singles(reputation)

    else:
        print(f'La IP no está registrada en VirusTotal.\n')
