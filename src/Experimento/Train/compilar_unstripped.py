import os
import subprocess
# Configurar carpeta temporal accesible para Docker dentro de /home/jorge/
tmp_dir = os.path.expanduser("~/tmp_xcross")
os.makedirs(tmp_dir, exist_ok=True)
os.environ["TMPDIR"] = tmp_dir
os.environ["TEMP"] = tmp_dir
os.environ["TMP"] = tmp_dir
# --- Configuración ---
CARPETA_ORIGEN = "./C"            # Archivos .c NUEVOS
CARPETA_DESTINO = "./salida"           # Carpeta para ejecutables stripped

TARGETS = [
    "x86_64-w64-mingw32"
]

# 1. Definimos los niveles de optimización a probar
OPTIMIZACIONES = ["-O0", "-O1", "-O2", "-O3", "-Os"]

os.makedirs(CARPETA_DESTINO, exist_ok=True)

archivos_c = [f for f in os.listdir(CARPETA_ORIGEN) if f.endswith('.c')]

if not archivos_c:
    print(f"No se encontraron archivos .c en '{CARPETA_ORIGEN}'")
    exit(1)

# 2. Bucle principal por Target
for target in TARGETS:
    
    # 3. Bucle por Nivel de Optimización
    for opt in OPTIMIZACIONES:
        # Quitamos el guion para crear una etiqueta limpia en el nombre de archivo (ej. "-O2" -> "O2")
        opt_tag = opt.replace("-", "")
        
        # 4. Bucle por Archivo .c
        for archivo in archivos_c:
            nombre_sin_extension = os.path.splitext(archivo)[0]
            extension = ".exe" if "mingw32" in target else ""
            
            # Nombre de salida compuesto: target + optimización + nombre_fichero
            nombre_salida = f"{target}_{opt_tag}_{nombre_sin_extension}{extension}"
            ruta_salida = os.path.join(CARPETA_DESTINO, nombre_salida)
            ruta_entrada = os.path.join(CARPETA_ORIGEN, archivo)
            
            comando = [
                "xcross",
                f"--target={target}",
                "gcc",
                opt,            # Flag de optimización (-O0, -O1, -O2, etc.)
                ruta_entrada,
                "-o", ruta_salida
            ]
            
            print(f"Compilando [{opt_tag}] (stripped): {archivo} -> {nombre_salida}")
            try:
                subprocess.run(comando, check=True)
                print(f"   Creado con éxito.")
            except subprocess.CalledProcessError:
                print(f"   Error al compilar {archivo} con {opt_tag} para {target}")


