"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP obtenida con el comando 'whois'.
"""


# Módulos necesarios
import os               # Ejecución de comandos del sistema


def get_info(ip: str) -> dict:
    """
    Obtiene la información de una IP a través del comando 'whois'.

    :param ip:  Dirección IP a buscar

    :return:    Diccionario con la información de la IP
    """
    try:
        output = os.popen(f"whois {ip}").read()

    except Exception as e:
        print(f'0\033[31m{e}\033[0m')
        exit(1)

    # Diccionario con la información de la IP
    data = {}

    # Marcadores de inicio y fin de la sección relevante (propio de 'whois')
    start_marker = "# start\n"
    end_marker = "# end\n"

    # Encontrar los marcadores de inicio y fin
    start_index = output.find(start_marker) + len(start_marker)     # Cursor detrás
    end_index = output.find(end_marker)                             # Cursor delante

    # Extraer la sección relevante de la salida
    lines = output[start_index:end_index].split("\n")

    # Procesar cada línea
    current_key = None
    current_value = ""

    for line in lines:
        line = line.strip()

        # La línea es un comentario o está vacía
        if line.startswith("#") or not line:
            continue

        if ":" in line:
            if current_key:
                data[current_key] = current_value.strip()

            current_key, current_value = map(str.strip, line.split(":", 1))

        else:
            current_value += " " + line.strip()

    # Agregar la última clave-valor al diccionario
    if current_key:
        data[current_key] = current_value.strip()

    return data


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\033[1mwhois\033[0m\n')  # Negrita

    result = get_info(ip)

    # Clave más larga
    max_key_len = max(map(len, result.keys())) + 1

    for key, value in result.items():
        print(f'{key:<{max_key_len}}: {value}')     # Alineado a la izquierda

