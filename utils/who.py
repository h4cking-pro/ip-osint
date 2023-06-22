"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP obtenida con el comando 'whois'.

Se usa la salida del comando 'whois' para extraer información, dicha
salida contiene muchos datos que son formateados de la siguiente forma:
- Sección: bloque de texto entre '# start' y '# end' de 'whois' (varios)
- Grupo: conjunto de líneas con una clave y un valor (varios/sección)
- Línea: par de clave y valor separados por ':' (varios/grupo)
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

    for line in lines:
        line = line.strip()

        # La línea es un comentario o está vacía
        if line and not line.startswith("#"):
            # La línea contiene una clave y un valor
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                # La clave ya existe
                if data.__contains__(key):
                    data[key] += f'\n{value}'   # Se concatena el valor

                else:
                    data[key] = value           # El valor se añade por primera vez

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
        # Comprobar cuántas líneas tiene el valor
        if '\n' not in value:
            print(f'{key:<{max_key_len}}: {value}')     # Alineado a la izquierda

        else:
            value_lines = value.split('\n')

            print(f'{key:<{max_key_len}}: {value_lines[0]}')

            # Mostrar el resto de líneas continuando el formato anterior
            for line in value_lines[1:]:
                print(f'{"":<{max_key_len}}  {line}')
