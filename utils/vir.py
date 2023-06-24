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


def _print_singles(reputation: dict):
    """
    Muestra la información de la IP que no requiere de un formato especial.

    :param reputation:  Diccionario con la información de la IP
    """
    country = get_country(reputation['country'])
    
    print(f'Sistema Autónomo (AS): {reputation["as_owner"]} ({reputation["asn"]}).')
    print(f'Perteneciente a {country}.')
    print()


def _print_multiples(reputation: dict):
    """
    Muestra la información de la IP que requiere de un formato especial.

    :param reputation:  Diccionario con la información de la IP
    """
    def _print_reputation_dict(elements: list):
        """
        Muestra el contenido de un elemento de reputación de VirusTotal.

        :param elements:  Lista con la información de la IP
        """
        if elements:
            for item in elements:
                date = datetime.strptime(item['date'], '%Y-%m-%d %H:%M:%S')\
                       .strftime('%d/%m/%Y\t%H:%M:%S')

                # Alineado a la izquierda
                print(f"\t{'sha256':<{max_len}}: {item['sha256']}")
                print(f"\t{'positivos':<{max_len}}: {item['positives']}")
                print(f"\t{'total':<{max_len}}: {item['total']}")
                print(f"\t{'fecha':<{max_len}}: {date}")
                print()

        else:
            print('\t\033[31mNo hay muestras disponibles.\033[0m')
            print()

    # Calcular la máxima longitud de los nombres
    max_len = max([len(key) for key, _ in reputation['detected_urls'][0].items()]) + 1

    print('URLs no detectadas:\n')
    for element in reputation['undetected_urls']:
        date = datetime.strptime(element[4], '%Y-%m-%d %H:%M:%S')\
               .strftime('%d/%m/%Y\t%H:%M:%S')

        # Alineado a la izquierda
        print(f"\t{'url':<{max_len}}: {element[0]}")
        print(f"\t{'sha256':<{max_len}}: {element[1]}")
        # print(f"\t{'positivos':<{max_len}}: {element[2]}\n")     # Siempre 0 por ser 'undetected_urls'
        print(f"\t{'total':<{max_len}}: {element[3]}")
        print(f"\t{'fecha':<{max_len}}: {date}")
        print()

    print('Muestras de remitentes no detectados:\n')
    _print_reputation_dict(reputation['undetected_referrer_samples'])

    print('Muestras de descargas no detectadas:\n')
    _print_reputation_dict(reputation['undetected_downloaded_samples'])

    print('Muestras de comunicaciones no detectadas:\n')
    _print_reputation_dict(reputation['undetected_communicating_samples'])

    print('Muestras de remitentes detectados:\n')
    _print_reputation_dict(reputation['detected_referrer_samples'])

    print('Muestras de descargas detectadas:\n')
    _print_reputation_dict(reputation['detected_downloaded_samples'])

    print('Muestras de comunicaciones detectadas:\n')
    _print_reputation_dict(reputation['detected_communicating_samples'])

    print('Resoluciones:\n')
    for element in reputation['resolutions']:
        date = datetime.strptime(element['last_resolved'], '%Y-%m-%d %H:%M:%S')\
            .strftime('%d/%m/%Y\t%H:%M:%S')

        # Alineado a la izquierda
        print(f"\t{'host':<{max_len}}: {element['hostname']}")
        print(f"\t{'fecha':<{max_len}}: {date}")
        print()


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\033[1mVirusTotal\033[0m\n')  # Negrita

    reputation = get_reputation(ip)

    if reputation:
        _print_singles(reputation)
        _print_multiples(reputation)

    else:
        print(f'La IP no está registrada en VirusTotal.\n')
