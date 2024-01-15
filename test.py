import os
import yaml

def modificar_yaml(archivo_origen, archivo_destino, clave, valor):
    with open(archivo_origen, 'r') as f:
        doc = yaml.safe_load(f)

    doc[clave] = valor

    with open(archivo_destino, 'w') as f:
        yaml.safe_dump(doc, f)

def procesar_carpeta(carpeta_origen, carpeta_destino, clave, valor):
    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    for nombre_archivo in os.listdir(carpeta_origen):
        if nombre_archivo.endswith('.yaml'):
            archivo_origen = os.path.join(carpeta_origen, nombre_archivo)
            archivo_destino = os.path.join(carpeta_destino, nombre_archivo)
            modificar_yaml(archivo_origen, archivo_destino, clave, valor)
if __name__ == "__main__":
    # Uso de la función
    procesar_carpeta('folder1/', 'folder2/', 'id', 'nuevo-id')
    print("{{BaseUrl}}")
