#!/usr/bin/env python3


# Módulos necesarios
import argparse         # Interpretación de argumentos
import json             # Interpretación de ficheros JSON

# Módulos propios
from utils import tor   # Análisis con TOR
from utils import sho   # Análisis con Shodan           (lib. API)
from utils import who   # Análisis con 'whois'
from utils import geo   # Análisis con geolocalización
from utils import vir   # Análisis con VirusTotal       (lib. API)


def get_parser():
    """
    Crea un analizador de argumentos para el script
    definiendo sus posibles opciones y características.

    :return:   El analizador de argumentos del script
    """

    # Crear el analizador de argumentos
    parser = argparse.ArgumentParser(description='IP Information Lookup')
    
    # Definir las posibles opciones y sus características
    parser.add_argument('-i', '--ip', metavar='IP',
                        help='IP address to check')
    parser.add_argument('-l', '--list', metavar='file',
                        help='text file with a list of IP addresses to check')
    parser.add_argument('-k', '--keys', metavar='file',
                        help='JSON file with API keys', default="keys.json")
    
    return parser


def set_keys_from_file(keys_file: str):
    """
    Obtiene las claves de las APIs de un fichero JSON
    y las almacena en las variables globales del script.
    """

    try:
        # Leer el fichero de claves API
        with open(keys_file, encoding="utf-8") as file:
            keys = json.load(file)

        # Comprobar que el fichero es válido
        if not ('vt' in keys and 'shodan' in keys):
            print('Error: los parámetros del fichero están mal definidos')
            exit(1)

        # Asignar las claves a las variables globales
        vir.set_api_key(keys['vt'])
        sho.set_api_key(keys['shodan'])

        # Comprobar la validez de las claves API
        # TODO

    except FileNotFoundError:
        print(f"\033[1;31mFichero '{keys_file}' no encontrado\033[0m")
        exit(1)

    except KeyError:
        print(f"\033[1;31mEl fichero '{keys_file}' no es válido\033[0m")
        exit(1)


def _is_valid(ip: str) -> bool:
    """
    Verifica que la IP pasada como argumento es válida.

    :param ip:  Dirección IP a verificar

    :return:    True si la IP es válida; False en caso contrario
    """
    octets = ip.split('.')  # Separar la IP en octetos

    if not ip.replace('.', '').isnumeric():
        print(f"\033[31mLa cadena '{ip}' no representa una IP.\033[0m")
        return False

    if len(octets) < 4:
        print(f"\033[31mLa IP '{ip}' es demasiado corta.\033[0m")
        return False

    elif 4 < len(octets):
        print(f"\033[31mLa IP '{ip}' es demasiado larga.\033[0m")
        return False

    for octet in octets:
        if not 0 <= int(octet) <= 255:
            print(f"\033[31mError en el octeto '{octet}' de la IP.\033[0m")
            return False

    return True


def _get_fails(ip_list: str) -> set:
    """
    Verifica que la lista de IPs pasada como argumento es válida.

    :param ip_list:  Lista de IPs a verificar

    :return:         Conjunto de IPs mal formadas.
    """
    fails = set()

    try:
        with open(ip_list, 'r') as file:
            for ip in file:
                if not _is_valid(ip.strip()):
                    fails.add(ip.strip())

    except FileNotFoundError:
        raise FileNotFoundError

    if fails:
        print(f"\033[31mSe encontraron {len(fails)} IPs mal formadas:\033[0m")

    return fails


def show_info(ip) -> None:
    """
    Procesa una IP y muestra la información obtenida.

    :param ip:  Dirección IP a procesar
    """
    print(f'\n\033[1;35mIP: {ip}\033[0m\n')

    tor.print_info(ip)
    print('\n')

    sho.print_info(ip)
    print('\n')

    who.print_info(ip)
    print('\n')

    geo.print_info(ip)
    print('\n')

    vir.print_info(ip)
    print('\n')


def main():
    """
    Función principal del script.
    """
    parser = get_parser()
    args = parser.parse_args()

    if args.keys:
        keys_file = args.keys

    # Establecer las claves de las APIs
    set_keys_from_file(keys_file)

    if args.ip:
        if _is_valid(args.ip):
            show_info(args.ip)

    elif args.list:
        try:
            fails = _get_fails(args.list)

            with open(args.list, 'r') as file:
                for ip in file:
                    if ip.strip() not in fails:
                        show_info(ip.strip())

        except FileNotFoundError:
            print(f"\033[31mFichero '{args.list}' no encontrado.\033[0m")
            exit(1)

    else:
        parser.print_help()


if __name__ == '__main__':
    """
    Punto de entrada al script.
    """
    try:

        main()

    except KeyboardInterrupt:
        exit(0)
