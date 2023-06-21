"""
El objetivo de este módulo es gestionar las distintas funcionalidades
del script principal relacionadas con la extracción de información de
una IP relacionada con la red Tor.

La fuente de datos actual es https://www.dan.me.uk/tornodes, cuya lista
de nodos fue procesada por @15Galan en un Gist usado en 'is_node()'.
"""

# Módulos necesarios
import requests  # Realizar peticiones HTTP

from utils.progressbar import ProgressBar  # Barra de progreso personalizada


def is_node(ip: str) -> list:
    """
    Verifica si una IP pertenece a la red TOR y extrae
    toda la información disponible sobre sus nodos.
    
    :param ip:  Dirección IP a verificar
    
    :return:    Información de los nodos que coinciden con la IP
    """
    # Extraer los datos de la fuente
    source = 'https://gist.githubusercontent.com/15Galan/63db51089da87a4b3491603f133cd668/' \
             'raw/7c1ff355ca25f2a19ccaa24f456c1dc8ab7059b6/tor-nodes.md'
    response = requests.get(source)
    rows = response.text.split('\n')[2:-1]  # Dividir por filas (sin cabeceras)
    progress = ProgressBar(len(rows))       # Cantidad de IPs a revisar

    # Resultado
    total = []

    print(f'Analizando {len(rows)} nodos:')

    # Analizar los datos
    for row in rows:
        # Se extraen los datos para cada fila de la tabla:
        # 1: separar cada celda de la fila de la tabla ('split()')
        # 2: eliminar los extremos generados por '|' ('[1:-1]')
        # 3: guardar la línea sin los espacios de las celdas ('strip()')
        row = [data.strip() for data in row.split('|')[1:-1]]

        if row[0] == ip:
            # Añadir el nodo a la lista de resultados
            total.append({
                "name": row[1],
                "router_port": row[2],
                "version": row[6],
                "contact": row[7],
                "flags": flags_translation(row[4])
            })

        # progress.update(info=row[0])  # Error en la salida de información
        progress.update()

    return total


def flags_translation(flags: str) -> set:
    """
    Traduce los flags de un nodo de la red TOR.
    
    :param flags:   Flags del nodo de salida en formato 'EFGHRSDVX'
    
    :return:        Conjunto con los flags traducidos
    """
    translation = set()

    # El campo 'flags' puede adoptar las letras 'ABEFGHRSDVX',
    # cada una corresponde a la inicial del nombre de un flag

    if 'A' in flags: translation.add('Authority')
    if 'B' in flags: translation.add('BadExit')
    if 'D' in flags: translation.add('V2Dir')
    if 'E' in flags: translation.add('Exit')
    if 'F' in flags: translation.add('Fast')
    if 'G' in flags: translation.add('Guard')
    if 'H' in flags: translation.add('HSDir')
    if 'R' in flags: translation.add('Running')
    if 'S' in flags: translation.add('Stable')
    if 'V' in flags: translation.add('Valid')
    if 'X' in flags: translation.add('StaleDesc')  # Suposición

    # Más información en:
    # https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/dir-spec.txt#L2336

    return translation


def print_info(ip: str):
    """
    Muestra la información formateada obtenida de la IP.

    :param ip:  Dirección IP a analizar
    """
    print('\033[1mTOR\033[0m\n')  # Negrita

    nodes = is_node(ip)
    count = len(nodes)

    print()     # Separar la barra de progreso del resto del texto

    if 0 == count:
        print('No se encontró información sobre la IP.\n')
        return None

    elif 1 == count:
        print('Se encontró 1 entrada para la IP.\n')

    elif 1 < count:
        print(f'Se encontraron {len(nodes)} entradas para la IP.\n')

    for node in nodes:
        print(f'Nombre:     {node["name"]}')
        print(f'Puerto:     {node["router_port"]}')
        print(f'Versión:    {node["version"]}')
        print(f'Contacto:   {node["contact"]}')
        print(f'Flags:      {sorted(node["flags"])}\n')
