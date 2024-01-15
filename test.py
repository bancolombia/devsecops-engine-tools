
import os

def listar_archivos(ruta):
    archivos = []
    for raiz, dirs, files in os.walk(ruta):
        for file in files:
            archivos.append(os.path.join(raiz, file))
    return archivos



if __name__ == "__main__":
    ruta_especifica = "/tools"  # Reemplaza esto con tu ruta específica
    archivos = listar_archivos(ruta_especifica)
    for archivo in archivos:
        print(archivo)


    ruta_actual = os.getcwd()
    print(ruta_actual)

