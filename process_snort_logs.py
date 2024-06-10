import psycopg2  # Importa la biblioteca per connectar-se i treballar amb bases de dades PostgreSQL
import re  # Importa la biblioteca per treballar amb expressions regulars (no s'utilitza en aquest codi específicament)
from datetime import datetime  # Importa la classe datetime per treballar amb dates i hores

# Funció para insertar dades en una taula específica
def insert_data(cursor, table, data):
    # Crea una cadena de placeholders per a cada valor de dades
    placeholders = ', '.join(['%s'] * len(data))
    # Combina les claus del diccionari de dades com a noms de columnes
    columns = ', '.join(data.keys())
    # Prepara la consulta SQL d'inserció
    sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
    try:
        print(f"Insertando en {table}: {data}")  # Mostra un missatge indicant quines dades s'estan inserint
        cursor.execute(sql, list(data.values()))  # Executa la consulta SQL amb els valors de dades
    except Exception as e:
        print(f"Error insertando en {table}: {e}")  # Mostra un missatge d'error si la inserció falla

# Conexión a la base de datos
try:
    conn = psycopg2.connect(
        dbname="snort_logs",  # Nom de la base de dades
        user="postgres",  # Nom d'usuari de la base de dades
        password="postgres",  # Contrasenya de l'usuari
        host="localhost",  # Adreça del servidor de la base de dades
        port="5432"  # Port del servidor de la base de dades
    )
    cursor = conn.cursor()  # Crea un cursor per interactuar amb la base de dades
    print("Conexión a la base de datos establecida correctamente.")  # Mostra un missatge d'èxit en establir la connexió
except Exception as e:
    print(f"Error conectando a la base de datos: {e}")  # Mostra un missatge d'error si la connexió falla
    exit(1)  # Termina el programa si no es pot connectar a la base de dades

# Funció per analitzar les línies del arxiu de log
def parse_line(line):
    try:
        parts = line.split()  # Divideix la línia en parts basades en espais
        datetime_str = parts[0]  # El primer element és la data i l'hora com a cadena
        timestamp = datetime.strptime(datetime_str, "%m/%d-%H:%M:%S.%f")  # Converteix la cadena a un objecte datetime
        year = datetime.now().year  # Obté l'any actual
        date = f"{year}-{timestamp.strftime('%m-%d')}"  # Formata la data com "any-mes-dia"
        time = timestamp.strftime("%H:%M:%S")  # Formata l'hora com "hora:minut:segon"
        src_ip = parts[-3].split(':')[0]  # Obté l'IP d'origen (tercer últim element)
        dst_ip = parts[-1].split(':')[0]  # Obté l'IP de destinació (últim element)
        description = " ".join(parts[1:-3])  # Combina els elements intermedis com a descripció
        return date, time, src_ip, dst_ip, description  # Retorna la data, hora, IP d'origen, IP de destinació i descripció
    except Exception as e:
        print(f"Error parsing line: {line}, {e}")  # Mostra un missatge d'error si el parsing falla
        return None  # Retorna None si hi ha un error

def process_logs():
    alertfile = "/var/log/snort/alertas.txt"  # Ruta del fitxer de log d'alertes
    try:
        with open(alertfile, 'r') as file:  # Obre el fitxer en mode lectura
            for line in file:
                print(f"Procesando línea: {line.strip()}")  # Mostra un missatge amb la línia que es processa
                parsed_data = parse_line(line)  # Analitza la línia
                if parsed_data:
                    date, time, src_ip, dst_ip, description = parsed_data  # Extreu les dades analitzades
                    print(f"Date: {date}, Time: {time}, IP de origen: {src_ip}, IP de destino: {dst_ip}, Description: {description}")

                    # Crea un diccionari amb les dades per inserir a la base de dades
                    ip_data = {
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'date': date,
                        'time': time,
                        'description': description
                    }
                    insert_data(cursor, 'ip_events', ip_data)  # Insereix les dades a la taula 'ip_events'
                    conn.commit()  # Confirma la transacció a la base de dades
                else:
                    print(f"No match found for line: {line.strip()}")  # Mostra un missatge si la línia no coincideix amb el format esperat
    except Exception as e:
        print(f"Error: {e}")  # Mostra un missatge d'error si hi ha un problema amb el fitxer
    finally:
        cursor.close()  # Tanca el cursor
        conn.close()  # Tanca la connexió a la base de dades
        print("Conexión a la base de datos cerrada")  # Mostra un missatge indicant que la connexió s'ha tancat

process_logs()  # Crida la funció per processar els logs
