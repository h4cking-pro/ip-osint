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
        show_info(args.ip)

    elif args.list:
        with open(args.list, 'r') as file:
            for ip in file:
                show_info(ip.strip())

    else:
        parser.print_help()


if __name__ == '__main__':
    """
    Punto de entrada al script.
    """
    main()
