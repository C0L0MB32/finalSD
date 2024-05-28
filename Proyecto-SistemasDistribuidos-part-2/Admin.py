from modificarBD import *
from getIP import get_ipv4
from datetime import datetime
import socket
import random
import mysql.connector
def menu_admin(conexion,is_master):
    ipv4=get_ipv4()
    while True:
        print("\nMenú de Administrador:")
        print("1. Ver usuarios")
        print("2. Agregar usuario")
        print("3. Editar usuario")
        print("4. Eliminar usuario")
        print("5. Ver ingenieros")
        print("6. Agregar ingeniero")
        print("7. Editar ingeniero")
        print("8. Eliminar ingeniero")
        print("9. Ver dispositivos")
        print("10. Agregar dispositivo")
        print("11. Eliminar dispositivo")
        print("12. Ver tickets")
        print("13. Eliminar ticket")
        print("14. Consultar folios de tickets")
        print("15. Salir")

        opcion = input("Seleccione una opción: ")

        if opcion == '1':
            ver_usuarios(conexion)
        elif opcion == '2':
                servidores_globales = leer_servidores_globales("remote_servers.txt")
                servidores_activos = leer_servidores_activos("active_nodes.txt", ipv4)
                enviar_mensaje_agregar_usuario(*obtener_datos_usuario(), servidores_activos)
        elif opcion == '3':
            servidores_globales = leer_servidores_globales("remote_servers.txt")
            servidores_activos = leer_servidores_activos("active_nodes.txt", ipv4)
            enviar_mensaje_editar_usuario(input("Ingresa el ID: "),*obtener_datos_usuario(), servidores_globales, servidores_activos)
        elif opcion == '4':
            servidores_globales = leer_servidores_globales("remote_servers.txt")
            servidores_activos = leer_servidores_activos("active_nodes.txt", ipv4)
            enviar_mensaje_eliminar_usuario(obtener_id(),servidores_globales, servidores_activos)
        elif opcion == '5':
            ver_ingenieros(conexion)
        elif opcion == '6':
            servidores_globales = leer_servidores_globales("remote_servers.txt")
            servidores_activos = leer_servidores_activos("active_nodes.txt", ipv4)
            enviar_mensaje_agregar_ingeniero(*obtener_datos_ingeniero())
        elif opcion == '7':
            servidores_globales = leer_servidores_globales("remote_servers.txt")
            servidores_activos = leer_servidores_activos("active_nodes.txt", ipv4)
            enviar_mensaje_editar_ingeniero(input("Ingresa el ID: "),*obtener_datos_ingeniero(), servidores_globales, servidores_activos)
        elif opcion == '8':
            servidores_globales = leer_servidores_globales("remote_servers.txt")
            servidores_activos = leer_servidores_activos("active_nodes.txt", ipv4)
            enviar_mensaje_eliminar_ingeniero(obtener_id(),servidores_globales, servidores_activos)
        elif opcion == '9':
            ver_dispositivos(conexion)
        elif opcion == '10':
            if is_master==ipv4:
                sucursal = obtener_sucursal_aleatoria("active_nodes.txt")
                # Enviar mensaje a todos los servidores activos
                servidores_globales = leer_servidores_globales("remote_servers.txt")
                servidores_activos = leer_servidores_activos("active_nodes.txt", ipv4)
                enviar_mensaje_agregar_dispositivo(ipv4, *obtener_datos_dispositivo(), sucursal, servidores_globales, servidores_activos)
                #insertar_datos_dispositivos(conexion, *obtener_datos_dispositivo(), sucursal)
            else:
                data=obtener_datos_dispositivo()
                mensaje= f"AGREGAR-MASTER, {data}"
                enviar_mensaje(is_master, obtener_puerto(is_master), mensaje)
                print("No tiene permisos para agregar dispositivos.")
        elif opcion == '11':
            servidores_globales = leer_servidores_globales("remote_servers.txt")
            servidores_activos = leer_servidores_activos("active_nodes.txt", ipv4)
            enviar_mensaje_eliminar_dispositivo(obtener_id(),servidores_globales, servidores_activos)
        elif opcion == '12':
            ver_tickets(conexion)
        elif opcion == '13':
            servidores_globales = leer_servidores_globales("remote_servers.txt")
            servidores_activos = leer_servidores_activos("active_nodes.txt", ipv4)
            enviar_mensaje_eliminar_ticket(obtener_id(),servidores_globales, servidores_activos)
        elif opcion == '14':
            consultar_folios(conexion)
        elif opcion == '15':
            print("¡Hasta luego, administrador!")
            break
        else:
            print("Opción inválida. Por favor, seleccione una opción válida.")


def menu_admin2(conexion,is_master,modelo, marca, anio):
    ipv4=get_ipv4()
    if is_master==ipv4:
        sucursal = obtener_sucursal_aleatoria("active_nodes.txt")
        # Enviar mensaje a todos los servidores activos
        servidores_globales = leer_servidores_globales("remote_servers.txt")
        servidores_activos = leer_servidores_activos("active_nodes.txt", ipv4)
        enviar_mensaje_agregar_dispositivo(ipv4, modelo, marca, anio, sucursal, servidores_globales, servidores_activos)
        #insertar_datos_dispositivos(conexion, *obtener_datos_dispositivo(), sucursal)
    else:
        print("ERROR AL COORDINAR DISPOSITIVOS")


def obtener_datos_usuario():
    nuevo_nombre = input("Nuevo nombre: ")
    nuevo_apellido = input("Nuevo apellido: ")
    nuevo_correo = input("Nuevo correo electrónico: ")
    nuevo_telefono = input("Nuevo número de teléfono: ")
    return nuevo_nombre, nuevo_apellido, nuevo_correo, nuevo_telefono

def obtener_datos_ingeniero():
    nuevo_nombre = input("Nuevo nombre: ")
    nuevo_apellido = input("Nuevo apellido: ")
    anios_experiencia = int(input("Años de experiencia: "))
    nuevo_telefono = input("Nuevo número de teléfono: ")
    return nuevo_nombre, nuevo_apellido, anios_experiencia, nuevo_telefono

def obtener_datos_dispositivo():
    modelo = input("Modelo: ")
    marca = input("Marca: ")
    anio = int(input("Año: "))
    #sucursal = int(input("Sucursal: "))
    return modelo, marca, anio

def obtener_id():
    return int(input("ID: "))

def obtener_sucursal_aleatoria(archivo_servidores_activos):
    try:
        with open(archivo_servidores_activos, "r") as file:
            servidores_activos = file.read().splitlines()
            if servidores_activos:
                ip_aleatoria = random.choice(servidores_activos)
                print(f"Se ha seleccionado aleatoriamente la IP: {ip_aleatoria}")
                return ip_aleatoria
            else:
                print("No hay IPs activas disponibles.")
                return None
    except Exception as e:
        print("Error al seleccionar una IP aleatoria:", e)
        return None

def leer_servidores_globales(archivo_servidores_globales):
    try:
        with open(archivo_servidores_globales, "r") as file:
            servidores_globales = [line.strip().split() for line in file.readlines()]
        return servidores_globales
    except Exception as e:
        print("Error al leer los servidores globales:", e)
        return []

def leer_servidores_activos(archivo_servidores_activos, ipv4):
    try:
        with open(archivo_servidores_activos, "r") as file:
            servidores_activos = [line.strip().split() for line in file.readlines() if line.strip().split()[0] != ipv4]
        return servidores_activos
    except Exception as e:
        print("Error al leer los servidores activos:", e)
        return []


def enviar_mensaje_agregar_dispositivo(ipv4, modelo, marca, anio, sucursal, servidores_globales, servidores_activos):
    try:
        # Formato del mensaje: "AGREGAR, modelo, marca, anio, sucursal"
        mensaje = f"AGREGAR, {modelo}, {marca}, {anio}, {sucursal}"

        # Leer las direcciones IP activas desde el archivo servidores_activos.txt
        with open('active_nodes.txt', 'r') as file:
            servidores_activos = file.readlines()

        # Eliminar los saltos de línea (\n) de cada dirección IP
        servidores_activos = [ip.strip() for ip in servidores_activos]

        # Enviar el mensaje a todas las direcciones IP activas
        for ip_destino in servidores_activos:
            enviar_mensaje(ip_destino, obtener_puerto(ip_destino), mensaje)

        print("Mensaje enviado correctamente a todas las direcciones IP activas.")
    except Exception as e:
        print("Error al enviar el mensaje:", e)

def enviar_mensaje_agregar_usuario(nombre, apellido, correo, telefono, servidores_activos):
    try:
        # Formato del mensaje: "AGREGAR_USUARIO, nombre, apellido, correo, telefono"
        mensaje = f"AGREGAR_USUARIO, {nombre}, {apellido}, {correo}, {telefono}"

        # Leer las direcciones IP activas desde el archivo servidores_activos.txt
        with open('active_nodes.txt', 'r') as file:
            servidores_activos = file.readlines()

        # Eliminar los saltos de línea (\n) de cada dirección IP
        servidores_activos = [ip.strip() for ip in servidores_activos]

        # Enviar el mensaje a todas las direcciones IP activas
        for ip_destino in servidores_activos:
            enviar_mensaje(ip_destino, obtener_puerto(ip_destino), mensaje)

        print("Mensaje enviado correctamente a todas las direcciones IP activas.")
    except Exception as e:
        print("Error al enviar el mensaje:", e)



def enviar_mensaje_agregar_ingeniero(nombre, apellido, aniosExperiencia, telefono):
    try:
        # Formato del mensaje: "AGREGAR_INGENIERO, nombre, apellido, aniosExperiencia, telefono"
        mensaje = f"AGREGAR_INGENIERO, {nombre}, {apellido}, {aniosExperiencia}, {telefono}"

        # Leer las direcciones IP activas desde el archivo servidores_activos.txt
        with open('active_nodes.txt', 'r') as file:
            servidores_activos = file.readlines()

        # Eliminar los saltos de línea (\n) de cada dirección IP
        servidores_activos = [ip.strip() for ip in servidores_activos]

        # Enviar el mensaje a todas las direcciones IP activas
        for ip_destino in servidores_activos:
            enviar_mensaje(ip_destino, obtener_puerto(ip_destino), mensaje)

        print("Mensaje enviado correctamente a todas las direcciones IP activas.")
    except Exception as e:
        print("Error al enviar el mensaje:", e)





def enviar_mensaje_eliminar_usuario(id, servidores_globales, servidores_activos):
    try:
        # Formato del mensaje: "AGREGAR, nombre, apellido, correo, telefono"
        mensaje = f"ELIMINAR_USUARIO, {id}"

        # Leer las direcciones IP activas desde el archivo servidores_activos.txt
        with open('active_nodes.txt', 'r') as file:
            servidores_activos = file.readlines()

        # Eliminar los saltos de línea (\n) de cada dirección IP
        servidores_activos = [ip.strip() for ip in servidores_activos]

        # Enviar el mensaje a todas las direcciones IP activas
        for ip_destino in servidores_activos:
            enviar_mensaje(ip_destino, obtener_puerto(ip_destino), mensaje)

        print("Mensaje enviado correctamente a todas las direcciones IP activas.")
    except Exception as e:
        print("Error al enviar el mensaje:", e)

def enviar_mensaje_eliminar_ingeniero(id, servidores_globales, servidores_activos):
    try:
        # Formato del mensaje: "AGREGAR, nombre, apellido, correo, telefono"
        mensaje = f"ELIMINAR_INGENIERO, {id}"

        # Leer las direcciones IP activas desde el archivo servidores_activos.txt
        with open('active_nodes.txt', 'r') as file:
            servidores_activos = file.readlines()

        # Eliminar los saltos de línea (\n) de cada dirección IP
        servidores_activos = [ip.strip() for ip in servidores_activos]

        # Enviar el mensaje a todas las direcciones IP activas
        for ip_destino in servidores_activos:
            enviar_mensaje(ip_destino, obtener_puerto(ip_destino), mensaje)

        print("Mensaje enviado correctamente a todas las direcciones IP activas.")
    except Exception as e:
        print("Error al enviar el mensaje:", e)

def enviar_mensaje_eliminar_dispositivo(id, servidores_globales, servidores_activos):
    try:
        # Formato del mensaje: "AGREGAR, nombre, apellido, correo, telefono"
        mensaje = f"ELIMINAR_DISPOSITIVO, {id}"

        # Leer las direcciones IP activas desde el archivo servidores_activos.txt
        with open('active_nodes.txt', 'r') as file:
            servidores_activos = file.readlines()

        # Eliminar los saltos de línea (\n) de cada dirección IP
        servidores_activos = [ip.strip() for ip in servidores_activos]

        # Enviar el mensaje a todas las direcciones IP activas
        for ip_destino in servidores_activos:
            enviar_mensaje(ip_destino, obtener_puerto(ip_destino), mensaje)

        print("Mensaje enviado correctamente a todas las direcciones IP activas.")
    except Exception as e:
        print("Error al enviar el mensaje:", e)

def enviar_mensaje_eliminar_ticket(id, servidores_globales, servidores_activos):
    try:
        # Formato del mensaje: "AGREGAR, nombre, apellido, correo, telefono"
        mensaje = f"ELIMINAR_TICKET, {id}"

        # Leer las direcciones IP activas desde el archivo servidores_activos.txt
        with open('active_nodes.txt', 'r') as file:
            servidores_activos = file.readlines()

        # Eliminar los saltos de línea (\n) de cada dirección IP
        servidores_activos = [ip.strip() for ip in servidores_activos]

        # Enviar el mensaje a todas las direcciones IP activas
        for ip_destino in servidores_activos:
            enviar_mensaje(ip_destino, obtener_puerto(ip_destino), mensaje)

        print("Mensaje enviado correctamente a todas las direcciones IP activas.")
    except Exception as e:
        print("Error al enviar el mensaje:", e)


def enviar_mensaje_editar_usuario(id_usuario, nuevo_nombre, nuevo_apellido, nuevo_correo, nuevo_telefono, servidores_globales, servidores_activos):
    try:
        # Formato del mensaje: "AGREGAR, nombre, apellido, correo, telefono"
        mensaje = f"EDITAR_USUARIO, {id_usuario}, {nuevo_nombre}, {nuevo_apellido}, {nuevo_correo}, {nuevo_telefono}"

        # Leer las direcciones IP activas desde el archivo servidores_activos.txt
        with open('active_nodes.txt', 'r') as file:
            servidores_activos = file.readlines()

        # Eliminar los saltos de línea (\n) de cada dirección IP
        servidores_activos = [ip.strip() for ip in servidores_activos]

        # Enviar el mensaje a todas las direcciones IP activas
        for ip_destino in servidores_activos:
            enviar_mensaje(ip_destino, obtener_puerto(ip_destino), mensaje)

        print("Mensaje enviado correctamente a todas las direcciones IP activas.")
    except Exception as e:
        print("Error al enviar el mensaje:", e)

def enviar_mensaje_editar_ingeniero(id_ingeniero, nuevo_nombre, nuevo_apellido, nueva_experiencia, nuevo_telefono, servidores_globales, servidores_activos):
    try:
        # Formato del mensaje: "AGREGAR, nombre, apellido, correo, telefono"
        mensaje = f"EDITAR_INGENIERO, {id_ingeniero}, {nuevo_nombre}, {nuevo_apellido}, {nueva_experiencia}, {nuevo_telefono}"

        # Leer las direcciones IP activas desde el archivo servidores_activos.txt
        with open('active_nodes.txt', 'r') as file:
            servidores_activos = file.readlines()

        # Eliminar los saltos de línea (\n) de cada dirección IP
        servidores_activos = [ip.strip() for ip in servidores_activos]

        # Enviar el mensaje a todas las direcciones IP activas
        for ip_destino in servidores_activos:
            enviar_mensaje(ip_destino, obtener_puerto(ip_destino), mensaje)

        print("Mensaje enviado correctamente a todas las direcciones IP activas.")
    except Exception as e:
        print("Error al enviar el mensaje:", e)


def enviar_mensaje_editar_dispositivo(id_dispositivo, nuevo_modelo, nueva_marca, nuevo_anio, sucursal_vieja, nueva_sucursal):
    try:
        # Formato del mensaje: "AGREGAR, nombre, apellido, correo, telefono"
        mensaje = f"EDITAR_DISPOSITIVO, {id_dispositivo}, {nuevo_modelo}, {nueva_marca}, {nuevo_anio}, {nueva_sucursal}"

        # Leer las direcciones IP activas desde el archivo servidores_activos.txt
        with open('active_nodes.txt', 'r') as file:
            servidores_activos = file.readlines()

        # Eliminar los saltos de línea (\n) de cada dirección IP
        servidores_activos = [ip.strip() for ip in servidores_activos]

        # Enviar el mensaje a todas las direcciones IP activas
        for ip_destino in servidores_activos:
            enviar_mensaje(ip_destino, obtener_puerto(ip_destino), mensaje)

        print("Mensaje enviado correctamente a todas las direcciones IP activas.")
    except Exception as e:
        print("Error al enviar el mensaje:", e)








def obtener_puerto(ip):
    try:
        with open("remote_servers.txt", "r") as file:
            for line in file:
                parts = line.strip().split()
                if len(parts) == 2 and parts[0] == ip:
                    return parts[1]  # Retorna el puerto asociado a la IP
        print(f"No se encontró el puerto asociado a la IP: {ip}")
        return None
    except Exception as e:
        print(f"Error al obtener el puerto de la IP {ip}: {e}")
        return None

def enviar_mensaje(ip_destino, puerto_destino, mensaje):
    try:
        # Crear un socket TCP/IP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Conectar al servidor destino
            s.connect((ip_destino, int(puerto_destino)))  # Convertir el puerto a entero
            # Enviar el mensaje
            s.sendall(mensaje.encode())
            print(f"Mensaje enviado a {ip_destino}:{puerto_destino}: {mensaje}")
    except Exception as e:
        print(f"Error al enviar mensaje a {ip_destino}:{puerto_destino}: {e}")


def actualizar_sucursales_inactivas(baseDeDatos):
    try:
        # Paso 1: Obtener las IPs activas desde el archivo active_nodes.txt
        with open("active_nodes.txt", "r") as file:
            active_ips = [line.strip() for line in file.readlines()]

        cursor = baseDeDatos.cursor()

        # Paso 2: Obtener las sucursales desde la tabla DISPOSITIVOS
        cursor.execute("SELECT id, sucursal FROM DISPOSITIVOS")
        dispositivos = cursor.fetchall()

        # Paso 3: Comparar las sucursales con las IPs activas y actualizar las inactivas
        for dispositivo in dispositivos:
            dispositivo_id, sucursal = dispositivo
            if sucursal not in active_ips:
                # Si la sucursal no está en las IPs activas, actualizar a una IP activa
                nueva_sucursal = obtener_sucursal_aleatoria("active_nodes.txt")  # Elegir la primera IP activa (puedes cambiar la lógica)
                id_dispositivo, nuevo_modelo, nueva_marca, nuevo_anio, sucursal_vieja=consultar_dispositivo_por_id(baseDeDatos, dispositivo_id)
                enviar_mensaje_editar_dispositivo(id_dispositivo, nuevo_modelo, nueva_marca, nuevo_anio, sucursal_vieja,nueva_sucursal)
                #cursor.execute("UPDATE DISPOSITIVOS SET sucursal = %s WHERE id = %s", (nueva_sucursal, dispositivo_id))
                print(f"Actualizando dispositivo {dispositivo_id}: {sucursal} -> {nueva_sucursal}")

        #baseDeDatos.commit()
        print("Actualización completada.")
    except Exception as e:
        print("Error al actualizar las sucursales inactivas:", e)
    finally:
        cursor.close()
