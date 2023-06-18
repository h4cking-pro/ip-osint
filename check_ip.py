#!/usr/bin/env python3


# Módulos necesarios
import argparse                     # Interpretación de argumentos
import json                         # Interpretación de ficheros JSON
import os                           # Ejecución de comandos del sistema

from requests import get            # Realización de peticiones HTTP
from shodan import Shodan           # API de Shodan
from socket import gethostbyaddr    # Búsqueda inversa de IPs



with open("keys.json", encoding="utf-8") as file:
    apis = json.load(file)

# Claves API extraídas del fichero 'keys.json'
VIRUSTOTAL_API_KEY = apis["vt"]
SHODAN_API_KEY = apis["shodan"]


def check_tor(ip) -> bool:
    """
    Verifica si una IP pertenece a la red TOR.
    
    :param ip:  Dirección IP a verificar
    
    :return:    True si pertenece a la red TOR; False en caso contrario
    """
    response = get(f'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={ip}')

    return ip in response.text


def shodan_info(ip: str, api: Shodan) -> str:
    """
    Realiza una búsqueda en Shodan de la IP especificada.

    :param ip:  Dirección IP a buscar
    :param api: Objeto de la API de Shodan

    :return:    Información de la IP en Shodan; mensaje de error en caso contrario
    """
    try:
        host = api.host(ip)
        data = f'IP: {host["ip_str"]}\n'
        data += f'Hostnames: {host.get("hostnames")}\n'
        data += f'Country: {host.get("country_name")}\n'
        data += f'Location: {host.get("latitude")}, {host.get("longitude")}\n'
        data += f'Organization: {host.get("org")}\n'
        data += f'Operating System: {host.get("os")}\n'
        data += f'Port: {host.get("ports")}\n'

        return data
    
    except Exception as e:
        return f'Error: \033[31m{e}\033[0m'


def reverse_ip_to_domain(ip) -> str or None:
    """
    Realiza una búsqueda inversa de la IP especificada.

    :param ip:  Dirección IP a buscar

    :return:    Nombre de dominio asociado a la IP; None en caso contrario
    """
    try:
        hostnames = gethostbyaddr(ip)
        return hostnames[0]
    
    except Exception as e:
        print(e)
        return None


def geolocate(ip) -> str or None:
    """
    Utiliza geolocalización para obtener información de una IP.

    :param ip:  Dirección IP a analizar

    :return:    Información de la IP; None en caso contrario
    """
    response = get(f'https://ipapi.co/{ip}/json/')
    
    if response.status_code == 200:
        result = json.loads(response.text)
        keys = result.keys()
        data = {'city', 'region', 'country_name', 'country_capital',
                'postal', 'latitude', 'longitude', 'languages'}

        return {key: result[key] for key in keys & data}  # Lista por comprensión

    return None


def virustotal_reputation(ip) -> str or None:
    """
    Verica la reputación de una IP en VirusTotal.

    :param ip:  Dirección IP a verificar

    :return:    Cadena con información; None en caso contrario
    """
    response = get(f'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={VIRUSTOTAL_API_KEY}&ip={ip}')

    if response.status_code == 200:
        return json.loads(response.text)

    return None


def main():
    """
    Función principal del script.
    """
    parser = argparse.ArgumentParser(description='IP Information Lookup')
    parser.add_argument('-i', '--ip', help='Single IP address')
    parser.add_argument('-l', '--list', help='File containing list of IP addresses')

    args = parser.parse_args()

    if args.ip:
        process_ip(args.ip)

    elif args.list:
        with open(args.list, 'r') as file:
            for ip in file:
                process_ip(ip.strip())

    else:
        parser.print_help()


def process_ip(ip) -> None:
    """
    Procesa una IP y muestra la información obtenida.

    :param ip:  Dirección IP a procesar
    """
    print(f'Checking IP: {ip}')

    # Verificar si es de TOR
    print("--------------------TOR-------------------")
    if check_tor(ip):
        print('TOR: Yes')
    else:
        print('TOR: No')

    print("--------------------SHODAN-------------------")
    # Verificar en Shodan
    shodan_result = shodan_info(ip, Shodan(SHODAN_API_KEY))
    if shodan_result:
        print('Shodan:')
        print(shodan_result)
    else:
        print('Shodan: No information available')

    # Realizar Whois
    print("--------------------WHOIS-------------------")
    whois_result = os.system(f'whois {ip}')
    print('Whois:')
    print(whois_result)

    # Realizar reverse ip lookup
    print("--------------------ReverseIpLookup-------------------")
    reverse_ip_to_domain_result = reverse_ip_to_domain(ip)
    if reverse_ip_to_domain_result:
        print(f'Reverse ip lookup: {reverse_ip_to_domain_result}')
    else:
        print('Reverse ip lookup: No information available')

    # Realizar Geolocalización
    print("--------------------GEOLOCALIZACIÓN-------------------")
    geolocate_result = geolocate(ip)
    if geolocate_result:
        print('Geolocation:')
        print(json.dumps(geolocate_result, indent=4))
    else:
        print('Geolocation: No information available')

    # Verificar reputación en VirusTotal
    print("--------------------VIRUSTOTAL-------------------")
    virustotal_result = virustotal_reputation(ip)
    if virustotal_result:
        print('VirusTotal Reputation:')
        print(json.dumps(virustotal_result, indent=4))
    else:
        print('VirusTotal Reputation: No information available')

    print('')


if __name__ == '__main__':
    main()
