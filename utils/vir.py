"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP relacionada con VirusTotal.
"""


# Módulos necesarios
import json                     # Interpretación de ficheros JSON
import requests                 # Realizar peticiones HTTP

from datetime import datetime   # Tratamiento de fecha y hora


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


def get_country(code: str) -> str:
    """
    Obtiene el nombre del país a partir de su código.

    :param code:    Código del país

    :return:        Nombre del país
    """
    try:
        response = requests.get(f'https://restcountries.com/v3.1/alpha/{code}')

        if response.status_code == 200:
            data = response.json()[0]

            # Obtener un emoji de la bandera
            flag = data['flag'] if 'flag' in data else '🏳️'

            # Comprobar si existe traducción en español ('spa')
            if 'spa' in data['translations']:
                return f"{data['translations']['spa']['common']} {flag}"

            elif 'name' in data:
                return f"{data['name']['common']} {flag}"

            else:
                return f'\033[31mDesconocido {flag}\033[0m'

        else:
            return '\033[31mmNo encontrado\033[0m'

    except requests.exceptions.RequestException:
        return '\033[31mmLa petición falló\033[0m'


def _print_as_info(reputation: dict):
    """
    Muestra la información de la IP que no requiere de un formato especial.

    :param reputation:  Diccionario con la información de la IP
    """
    country = get_country(reputation['country'])
    
    # Mostrar información sobre el AS, ASN y su país
    print(f'Sistema Autónomo (AS): {reputation["as_owner"]} ({reputation["asn"]}).')
    print(f'Perteneciente a {country}.\n')


def _print_reputation_dict(rep: dict, dict_id: str, align: int):
    """
    Muestra el contenido de un elemento de reputación de VirusTotal.

    :param rep:     Objeto de reputación de VirusTotal
    :param dict_id: Identificador del elemento de la reputación a mostrar
    :param align:   Cantidad de caracteres para alinear las claves
    """
    if rep.get(dict_id):
        for item in rep[dict_id]:
            date = datetime.strptime(item['date'], '%Y-%m-%d %H:%M:%S')\
                   .strftime('%d/%m/%Y\t%H:%M:%S')

            # Alineado a la izquierda
            print(f"\t{'sha256':<{align}}: {item['sha256']}")
            print(f"\t{'positivos':<{align}}: {item['positives']}")
            print(f"\t{'total':<{align}}: {item['total']}")
            print(f"\t{'fecha':<{align}}: {date}\n")

    else:
        print('\tNo hay muestras disponibles.\n')


def _print_all_reputation_dicts(reputation: dict):
    """
    Muestra la información de la IP que requiere de un formato especial.

    :param reputation:  Diccionario con la información de la IP
    """
    max_len = 10    # Longitud de la clave más larga en español: 'positivos' + 1

    print('URLs no detectadas:\n')      # Caso especial: los datos no tienen claves
    if reputation.get('undetected_urls'):
        for element in reputation['undetected_urls']:
            date = datetime.strptime(element[4], '%Y-%m-%d %H:%M:%S')\
                   .strftime('%d/%m/%Y\t%H:%M:%S')

            # Alineado a la izquierda
            print(f"\t{'url':<{max_len}}: {element[0]}")
            print(f"\t{'sha256':<{max_len}}: {element[1]}")
            # print(f"\t{'positivos':<{max_len}}: {element[2]}\n")     # Siempre 0 por ser 'undetected_urls'
            print(f"\t{'total':<{max_len}}: {element[3]}")
            print(f"\t{'fecha':<{max_len}}: {date}\n")

    else:
        print('\tNo hay información disponible.\n')

    print('Muestras de remitentes no detectados:\n')
    _print_reputation_dict(reputation, 'undetected_referrer_samples', max_len)

    print('Muestras de descargas no detectadas:\n')
    _print_reputation_dict(reputation, 'undetected_downloaded_samples', max_len)

    print('Muestras de comunicaciones no detectadas:\n')
    _print_reputation_dict(reputation, 'undetected_communicating_samples', max_len)

    print('Muestras de remitentes detectados:\n')
    _print_reputation_dict(reputation, 'detected_referrer_samples', max_len)

    print('Muestras de descargas detectadas:\n')
    _print_reputation_dict(reputation, 'detected_downloaded_samples', max_len)

    print('Muestras de comunicaciones detectadas:\n')
    _print_reputation_dict(reputation, 'detected_communicating_samples', max_len)

    print('Resoluciones:\n')                    # Casos especiales: estructura distinta
    if reputation.get('resolutions'):
        for element in reputation['resolutions']:
            date = datetime.strptime(element['last_resolved'], '%Y-%m-%d %H:%M:%S')\
                .strftime('%d/%m/%Y\t%H:%M:%S')

            # Alineado a la izquierda
            print(f"\t{'host':<{max_len}}: {element['hostname']}")
            print(f"\t{'fecha':<{max_len}}: {date}\n")

    else:
        print('\tNo hay información disponible.\n')


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\033[1mVirusTotal\033[0m\n')  # Negrita

    reputation = get_reputation(ip)

    if reputation:
        _print_as_info(reputation)
        _print_all_reputation_dicts(reputation)

    else:
        print(f'La IP no está registrada en VirusTotal.\n')
