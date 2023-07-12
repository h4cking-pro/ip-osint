"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP relacionada con geolocalización.
"""


# Módulos necesarios
import json                         # Interpretación de ficheros JSON
import requests                     # Realizar peticiones HTTP
import socket                       # Realizar operaciones de red

from utils.vir import get_country   # Obtener el nombre de un país a partir de su código


def reverse_ip_to_domain(ip) -> str or None:
    """
    Realiza una búsqueda inversa de la IP especificada.

    :param ip:  Dirección IP a buscar

    :return:    Nombre de dominio asociado a la IP;
                None en caso contrario
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    
    except socket.herror:
        return f"\033[1mNo se pudo resolver '{ip}'.\033[0m"

    except socket.gaierror:
        return f"\033[1mLa IP '{ip}' no es válida.\033[0m"

    except socket.timeout:
        return f"\033[1mTiempo de conexión agotado.\033[0m"


def _handle_accent(text):
    """
    Cambia las combinaciones de caracteres que representan
    acentos por sus equivalentes con acento.

    :param text:    Texto a modificar

    :return:        Texto con acentos
    """
    if type(text) is str:
        text = text.replace('Ã¡', 'á').replace('Ã', 'Á')
        text = text.replace('Ã©', 'é').replace('Ã‰', 'É')
        text = text.replace('Ã­', 'í').replace('Ã', 'Í')
        text = text.replace('Ã³', 'ó').replace('Ã“', 'Ó')
        text = text.replace('Ãº', 'ú').replace('Ãš', 'Ú')
        text = text.replace('Ã±', 'ñ').replace('Ã‘', 'Ñ')

    return text


def geolocate(ip) -> dict:
    """
    Utiliza geolocalización para obtener información de una IP.

    :param ip:  Dirección IP a analizar

    :return:    Diccionario con la información de la IP
    """
    response = requests.get(f'https://ipapi.co/{ip}/json/')
    data = {}

    if response.status_code == 200:
        location = json.loads(response.text)

        # Filtrar las claves del resultado por las indicadas
        for key in location.keys() & {'city', 'region', 'postal', 'latitude', 'longitude'}:
            if location[key]:
                data[key] = _handle_accent(location[key])

            else:
                data[key] = '\033[31mSin información\033[0m'

        if 'country_code' in location.keys():
            data['country'] = get_country(location['country_code'])     # País traducido

    return data


def _print_geolocation_info(ip: str):
    """
    Muestra la información obtenida de la IP
    relacionada con la geolocalización de la misma.

    :param ip:  Dirección IP a analizar
    """
    print('\n\033[1mGeolocalización\033[0m\n')  # Negrita

    geolocation = geolocate(ip)

    if geolocation:
        max_key_len = 12  # Lo que mide 'Coordenadas' + 1; claves ya traducidas
        coordinates = f"({geolocation['latitude']}, {geolocation['longitude']})"

        print(f'{"País":<{max_key_len}}: {geolocation["country"]}')
        print(f'{"Región":<{max_key_len}}: {geolocation["region"]}')
        print(f'{"Ciudad":<{max_key_len}}: {geolocation["city"]}')
        print(f'{"Cód. Postal":<{max_key_len}}: {geolocation["postal"]}')
        print(f'{"Coordenadas":<{max_key_len}}: {coordinates}')

    else:
        print('\033[31mNo se pudo obtener información de la IP.\033[0m')


def _print_reverse_info(ip: str):
    """
    Muestra la información obtenida de la IP relacionada
    con la búsqueda inversa de dominios de la misma.

    :param ip:  Dirección IP a analizar
    """
    print('\n\033[1mBúsqueda Inversa de IP\033[0m\n')   # Negrita

    reverse_ip = reverse_ip_to_domain(ip)

    if reverse_ip:
        print(reverse_ip)

    else:
        print('\033[31mNo se pudo obtener información de búsqueda inversa\033[0m')


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    _print_geolocation_info(ip)
    _print_reverse_info(ip)
