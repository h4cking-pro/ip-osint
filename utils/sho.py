"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP relacionada con el buscador Shodan.
"""


# Módulos necesarios
from shodan import Shodan, APIError     # Shodan API


# Variables globales
_SHODAN_API_KEY = None      # Clave de la API de Shodan


def key_information(shodan_api):
    try:
        info = shodan_api.info()
        
        for i in info:
            print(f'{i}: {info[i]}')

    except APIError as e:
        print(f'0\033[31m{e}\033[0m')


def set_api_key(key: str) -> None:
    """
    Establece la clave de la API para poder
    usar las funcionalidades de este módulo.

    :param key:     Una clave API de Shodan
    """
    global _SHODAN_API_KEY
    
    _SHODAN_API_KEY = key


def get_api_key() -> str:
    """
    Obtiene la clave API definida en este módulo.

    :return:    La clave API de Shodan
    """
    return _SHODAN_API_KEY


def get_info(ip: str) -> str:
    """
    Realiza una búsqueda en Shodan de la IP especificada.

    :param ip:  Dirección IP a buscar

    :return:    Información de la IP en Shodan; mensaje de error en caso contrario
    """
    try:
        obj = Shodan(_SHODAN_API_KEY)
        host = obj.host(ip)

        data  = f'IP:           {host["ip_str"]}\n'
        data += f'Dominios:     {host.get("hostnames")}\n'
        data += f'País:         {host.get("country_name")}\n'
        data += f'Localización: ({host.get("latitude")}, {host.get("longitude")})\n'
        data += f'Organización: {host.get("org")}\n'
        data += f'Sistema Op.:  {host.get("os")}\n'
        data += f'Puertos:      {host.get("ports")}\n'

        return data
    
    except APIError as e:
        return f'\033[31m{e}\033[0m'
    
    except Exception as e:
        return f'\033[31m{e}\033[0m'


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\033[1mShodan\033[0m\n')  # Negrita

    shodan = get_info(ip)

    if shodan:
        print(shodan)
    else:
        print(f'\033[31mInformación no disponible\033[0m')
