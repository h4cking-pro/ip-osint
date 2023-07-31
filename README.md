<div align="center">
    <p>
        <img src=".github/readme/h4cking-pro light.png#gh-light-mode-only" alt="H4 logo (claro)" width="450" />
        <img src=".github/readme/h4cking-pro dark.png#gh-dark-mode-only" alt="H4 logo (oscuro)" width="450" />
    </p>
    Un script simple para obtener información de una IP
</div>


# Descripción

Este es un script enfocado al OSINT (*Open Source Intelligence*) cuyo objetivo
principal consiste en obtener información de una IP usando distintas fuentes de
información; actualmente se usan las siguientes:

- [ipapi.co](https://ipapi.co)
- [dan.me.uk](https://dan.me.uk)
- [WHOIS](https://es.wikipedia.org/wiki/WHOIS)
- [Shodan.io](https://shodan.io) (requiere una clave API)
- [VirusTotal](https://virustotal.com) (requiere una clave API)


# Instalación

1. Instalar [Python 3](https://www.python.org/downloads).
2. Clonar el repositorio.
3. Instalar las dependencias (`pip install -r requirements.txt`).


# Ejecución

> **Note**  
> **Claves API**  
> Necesitarás una clave API de Shodan y de VirusTotal para que el script obtenga la
> información asociada a esas fuentes de información; si no se proporcionan, el script
> funcionará con normalidad, ignorándolas.
> 
> **Salida formateada del terminal**  
> El script está diseñado para mostrar la información de forma legible en el terminal,
> lo que incluye colores, negritas, etc. esto puede explicar la presencia de caracteres
> extraños en la salida en elagunas terminales.

Este script puede usarse como un comando de terminal o con `python3`.

Otorga permisos de ejecución al script principal `main.py` y el sistema lo ejecutará
con el intérprete de Python:

```shell
sudo chmod +x main.py
```

A partir de aquí, puedes consultar la ayuda con la opción `-h` o `--help`:

```shell
./main.py -h
```

```
usage: main.py [-h] [-i IP] [-l file] [-k file]

IP Information Lookup

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        IP address to check
  -l file, --list file  text file with a list of IP addresses to check
  -k file, --keys file  JSON file with API keys
```

También es posible usarlo como un módulo de Python de la forma habitual:

```shelll
python3 main.py <args>
```

## Argumentos

El proyecto funciona con 3 tipos de argumentos distintos, pero si no se proporciona
ninguno, su comportamiento por defecto es mostrar la ayuda (equivalente a `./main.py -h`).

### `-ip` / `--ip`

El script recibe una IP como argumento de entrada y comprueba que sea válida.

Si todo es correcto, analizará la información de la IP obtenida desde las fuentes
encionadas al inicio y la mostrará por pantalla en un formato legible; en caso
contrario, mostrará un mensaje de error y terminará.

### `-l` / `--list`

El script recibe un archivo de texto con una lista de IPs y comprueba que sean válidas.

Primero se mostrarán los errores de las IPs no válidas del fichero; después se procederá
a ejecutar la acción descrita en el apartado anterior para cada IP válida del mismo.

### `-k` / `--keys`

El script recibe un archivo JSON con las claves API de Shodan y VirusTotal; si este
argumento no se proporciona, usará el fichero por defecto ubicado en la raíz.

Si el fichero contiene las claves en un formato correcto, el script las usará para
realizar las acciones descritas en los apartados anteriores.
