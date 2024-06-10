import psycopg2
import re
from datetime import datetime

# Función para insertar datos en una tabla específica
def insert_data(cursor, table, data):
    placeholders = ', '.join(['%s'] * len(data))
    columns = ', '.join(data.keys())
    sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
    try:
        print(f"Insertando en {table}: {data}")
        cursor.execute(sql, list(data.values()))
    except Exception as e:
        print(f"Error insertando en {table}: {e}")

# Conexión a la base de datos
try:
    conn = psycopg2.connect(
        dbname="snort_logs",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )
    cursor = conn.cursor()
    print("Conexión a la base de datos establecida correctamente.")
except Exception as e:
    print(f"Error conectando a la base de datos: {e}")
    exit(1)

# Función para analizar las líneas del archivo de log
def parse_line(line):
    try:
        parts = line.split()
        datetime_str = parts[0]
        timestamp = datetime.strptime(datetime_str, "%m/%d-%H:%M:%S.%f")
        year = datetime.now().year
        date = f"{year}-{timestamp.strftime('%m-%d')}"
        time = timestamp.strftime("%H:%M:%S")
        src_ip = parts[-3].split(':')[0]
        dst_ip = parts[-1].split(':')[0]
        description = " ".join(parts[1:-3])  # Extraer la descripción
        return date, time, src_ip, dst_ip, description
    except Exception as e:
        print(f"Error parsing line: {line}, {e}")
        return None

def process_logs():
    alertfile = "/var/log/snort/alertas.txt"
    try:
        with open(alertfile, 'r') as file:
            for line in file:
                print(f"Procesando línea: {line.strip()}")
                parsed_data = parse_line(line)
                if parsed_data:
                    date, time, src_ip, dst_ip, description = parsed_data
                    print(f"Date: {date}, Time: {time}, IP de origen: {src_ip}, IP de destino: {dst_ip}, Description: {description}")

                    ip_data = {
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'date': date,
                        'time': time,
                        'description': description
                    }
                    insert_data(cursor, 'ip_events', ip_data)
                    conn.commit()
                else:
                    print(f"No match found for line: {line.strip()}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        conn.close()
        print("Conexión a la base de datos cerrada")

process_logs()
