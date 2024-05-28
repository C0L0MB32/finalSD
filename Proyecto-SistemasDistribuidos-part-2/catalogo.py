from modificarBD import *

def determinar_func(conexion,mensaje):
    partes = mensaje.split(',')
    palabra_clave = partes[0].strip()
    print(palabra_clave)
    # Los datos comienzan después de la palabra clave, así que los recogemos desde la siguiente posición
    datos = [parte.strip() for parte in partes[1:]]


    if(palabra_clave == 'AGREGAR_USUARIO'):
        nombre, apellido, correo, telefono = datos
        insertar_datos_usuarios(conexion, nombre, apellido, correo, telefono)
    elif(palabra_clave == 'AGREGAR_INGENIERO'):
        nombre,apellido,aniosExperiencia,telefono = datos
        insertar_datos_ingenieros(conexion,nombre,apellido,aniosExperiencia,telefono)
    elif(palabra_clave == 'AGREGAR_TICKET'):#PENDIENTE
        usuario_id, ingeniero_id, dispositivo_id, descripcion, fecha,sucursal = datos
        insertar_datos_tickets(conexion,usuario_id, ingeniero_id, dispositivo_id, descripcion, fecha,sucursal)
    elif(palabra_clave == 'ELIMINAR_USUARIO'):
        id_usuario = datos
        eliminar_usuario(conexion, id_usuario)
    elif(palabra_clave == 'ELIMINAR_INGENIERO'):
        id_ingeniero = datos
        eliminar_ingeniero(conexion, id_ingeniero)
    elif(palabra_clave == 'ELIMINAR_DISPOSITIVO'):
        id_dispositivo = datos
        eliminar_dispositivo(conexion, id_dispositivo)
    elif(palabra_clave == 'ELIMINAR_TICKET'):
        id_ticket = datos
        eliminar_ticket(conexion, id_ticket)
    elif(palabra_clave == 'EDITAR_USUARIO'):
        id_usuario, nuevo_nombre, nuevo_apellido, nuevo_correo, nuevo_telefono = datos
        editar_datos_usuario(conexion, id_usuario, nuevo_nombre, nuevo_apellido, nuevo_correo, nuevo_telefono)
    elif(palabra_clave == 'EDITAR_INGENIERO'):
        id_ingeniero, nuevo_nombre, nuevo_apellido, nueva_experiencia, nuevo_telefono = datos
        editar_datos_ingeniero(conexion, id_ingeniero, nuevo_nombre, nuevo_apellido, nueva_experiencia, nuevo_telefono)
    # elif(palabra_clave == 'EDITAR_DISPOSITIVO'):
    #     editar_datos_dispositivo()
    elif(palabra_clave == 'EDITAR_TICKET'):
        id_ticket, nueva_descripcion, nuevo_estado, nuevo_ingeniero_id, nuevo_dispositivo_id = datos
        editar_datos_ticket(conexion, id_ticket, nueva_descripcion, nuevo_estado, nuevo_ingeniero_id, nuevo_dispositivo_id)
    else:
        pass