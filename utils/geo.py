"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP relacionada con geolocalización.
"""


# Módulos necesarios
import json                         # Interpretación de ficheros JSON
import requests                     # Realizar peticiones HTTP
import socket                       # Realizar operaciones de red


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
        return f"\033[1mNo se pudo resolver el nombre para '{ip}'\033[0m"
    
    except socket.gaierror:
        return f"\033[1mLa IP '{ip}' no es válida\033[0m"
    
    except socket.timeout:
        return f"\033[1mTiempo de conexión agotado\033[0m"


def geolocate(ip) -> str or None:
    """
    Utiliza geolocalización para obtener información de una IP.

    :param ip:  Dirección IP a analizar

    :return:    Información de la IP; None en caso contrario
    """
    response = requests.get(f'https://ipapi.co/{ip}/json/')
    
    if response.status_code == 200:
        result = json.loads(response.text)
        keys = result.keys()
        data = {'city', 'region', 'country_name', 'country_capital',
                'postal', 'latitude', 'longitude', 'languages'}

        return {key: result[key] for key in keys & data}  # Lista por comprensión

    return None


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\n\033[1mGeolocalización\033[0m\n')     # Negrita
    
    geolocation = geolocate(ip)

    if geolocation:
        print(json.dumps(geolocation, indent=4))

    else:
        print('\033[31mNo se pudo obtener información de geolocalización\033[0m')

    print('\n\033[1mBúsqueda Inversa de IP\033[0m\n')     # Negrita
    
    reverse_ip = reverse_ip_to_domain(ip)

    if reverse_ip:
        print(reverse_ip)

    else:
        print('\033[31mNo se pudo obtener información de búsqueda inversa\033[0m')
