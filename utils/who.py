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


# Variables globales
OUTPUT: str = ''        # Salida de 'whois'


def _get_sections(start="# start\n\n", end="\n\n# end") -> list:
    """
    Obtiene las secciones relevantes de la salida del comando
    'whois', identificadas por los marcadores de inicio y fin.

    :param start:   Inicio de la sección (por defecto: '# start\n')
    :param end:     Final de la sección (por defecto: '# end\n')

    :return:        Lista de secciones relevantes
    """
    global OUTPUT

    # Encontrar los marcadores de inicio y fin
    start_index = OUTPUT.find(start) + len(start)   # Cursor detrás
    end_index = OUTPUT.find(end)                    # Cursor delante

    # Secciones relevantes
    relevant_data = []

    # Buscar todas las secciones relevantes
    while start_index != -1 and end_index != -1:
        relevant_data.append(OUTPUT[start_index:end_index])

        # Encontrar los siguientes marcadores
        start_index = OUTPUT.find(start, start_index) + len(start)  # Cursor detrás
        end_index = OUTPUT.find(end, end_index + 1)                 # Cursor delante

    return relevant_data


def _get_groups(section: str) -> list:
    """
    Obtiene los grupos de información de una sección.

    :param section: Sección de información

    :return:        Lista de grupos de información
    """
    groups = []     # Grupos de información
    group = ''      # Grupo actual (auxiliar)

    # Recorrer la sección y almacenar los grupos de información
    for line in section.split('\n'):
        line = line.strip()

        if line:
            group += line + '\n'        # Se añade la línea al grupo

        elif group:
            groups.append(group[:-1])   # Se añade el grupo a la lista (sin el '\n' final)

        if not line:
            group = ''                  # Se vacía el grupo actual

    if group:
        groups.append(group[:-1])       # Se añade el último grupo a la lista

    return groups


def _get_lines(group: str) -> list:
    """
    Obtiene las líneas de información de un grupo.

    :param group:   Grupo de información

    :return:        Lista de líneas de información
    """
    # Esta función es bastante redundante, pero
    # hace más legible el código de 'get_info()'

    return group.split('\n')


def get_info(ip: str) -> list:
    """
    Obtiene la información de una IP a través del comando 'whois'.

    :param ip:  Dirección IP a buscar

    :return:    Lista de secciones relevantes de información de la IP
    """
    global OUTPUT

    try:
        OUTPUT = os.popen(f"whois {ip}").read()

    except Exception as e:
        print(f'0\033[31m{e}\033[0m')
        return []

    info = []   # Información de la IP

    # Encontrar todas las secciones relevantes      # Complejidad: O(n^3)
    for section in _get_sections():
        current_section = []
        for group in _get_groups(section):
            current_group = {}
            for line in _get_lines(group):
                key, value = line.split(":", 1)             # Extraer clave-valor
                key, value = key.strip(), value.strip()     # Eliminar espacios

                if not value:                               # Valor vacío
                    value = '\033[31mSin información\033[0m'

                # Si la clave ya existe se le añade el valor
                if current_group.__contains__(key):
                    current_group[key] += f'\n{value}'  # Clave repetida

                else:
                    current_group[key] = value          # Clave nueva

            current_section.append(current_group)

        info.append(current_section)

    return info


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\033[1mwhois\033[0m\n')  # Negrita

    whois_info = get_info(ip)

    if not whois_info:
        print('\033[31mNo se pudo obtener información de la IP.\033[0m')
        return
    
    count = 1

    # Calcular el tamaño máximo de las claves
    max_key_len = max([len(key) for section in whois_info for group in section for key in group]) + 1

    for section in whois_info:
        print(f'Sección {count}/{len(whois_info)}\n')   # Título de la sección
        count += 1

        for group in section:
            for key, value in group.items():
                # Comprobar cuántas líneas tiene el valor
                if '\n' not in value:
                    print(f'{key:<{max_key_len}}: {value}')     # Alineado a la izquierda

                else:
                    value_lines = value.split('\n')

                    print(f'{key:<{max_key_len}}: {value_lines[0]}')

                    # Mostrar el resto de líneas continuando el formato anterior
                    for line in value_lines[1:]:
                        print(f'{"":<{max_key_len}}  {line}')

            print()     # Separador entre grupos

        print()         # Separador entre secciones
