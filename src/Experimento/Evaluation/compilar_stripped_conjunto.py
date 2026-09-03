import os
import subprocess
from datetime import datetime

# --- Solución al problema de montajes temporales en Docker / VirtualBox ---
TMP_DIR = os.path.expanduser("~/tmp_xcross")
os.makedirs(TMP_DIR, exist_ok=True)
os.environ["TMPDIR"] = TMP_DIR
os.environ["TEMP"] = TMP_DIR
os.environ["TMP"] = TMP_DIR

# --- Configuración ---
CARPETA_ORIGEN = "./C_2"            # Archivos .c y .h del proyecto
CARPETA_DESTINO = "./salida"        # Carpeta para ejecutables stripped
NOMBRE_PROYECTO = "programa"       # Nombre base para el ejecutable resultante
ARCHIVO_INFORME = "informe_compilacion.txt"

TARGETS = [
    "mips-unknown-linux-musl",
    "mips-unknown-linux-gnu",
    "mips64-unknown-linux-gnu",
    "mips64-unknown-linux-uclibcn32",
    "mips64-unknown-linux-uclibcn64",
    "arm64-unknown-linux-musl",
    "arm64-unknown-linux-gnu",
    "arm64-unknown-linux-uclibc",
    "ppc-unknown-linux-musl",
    "ppc-unknown-linux-gnu",
    "ppc-unknown-linux-uclibc",
    "sparc-unknown-linux-uclibc",
    "sparc64-unknown-linux-gnu",
    "x86_64-w64-mingw32"
]

OPTIMIZACIONES = ["-O0", "-O1", "-O2", "-O3", "-Os"]

os.makedirs(CARPETA_DESTINO, exist_ok=True)

# Buscar todos los archivos .c dentro de la carpeta origen
archivos_c = [f for f in os.listdir(CARPETA_ORIGEN) if f.endswith('.c')]

if not archivos_c:
    print(f"No se encontraron archivos .c en '{CARPETA_ORIGEN}'")
    exit(1)

# Construir las rutas completas de todos los archivos .c para la compilación conjunta
rutas_c = [os.path.join(CARPETA_ORIGEN, f) for f in archivos_c]

# Inicializar cabecera principal del archivo de informe
with open(ARCHIVO_INFORME, "w", encoding="utf-8") as f_informe:
    f_informe.write("=" * 80 + "\n")
    f_informe.write("         INFORME DETALLADO DE COMPILACIÓN CONJUNTA DE MANTILLA         \n")
    f_informe.write(f"Fecha de inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f_informe.write(f"Total de fuentes C incluidos en el proyecto: {len(archivos_c)}\n")
    f_informe.write(f"Total de targets: {len(TARGETS)}\n")
    f_informe.write(f"Niveles de optimización: {', '.join(OPTIMIZACIONES)}\n")
    f_informe.write("=" * 80 + "\n\n")

# Bucle principal por Target
for target in TARGETS:
    # Bucle por Nivel de Optimización
    for opt in OPTIMIZACIONES:
        opt_tag = opt.replace("-", "")
        extension = ".exe" if "mingw32" in target else ""
        
        # Nombre de salida combinando target, optimización y nombre del proyecto
        nombre_salida = f"{target}_{opt_tag}_{NOMBRE_PROYECTO}{extension}"
        ruta_salida = os.path.join(CARPETA_DESTINO, nombre_salida)
        
        # Comando de compilación conjunto (incluye todos los .c, el include -I, -s y opt)
        comando = [
            "xcross",
            f"--target={target}",
            "gcc"
        ] + rutas_c + [
            f"-I{CARPETA_ORIGEN}",  # Incluye cabeceras .h
            "-s",                   # Elimina símbolos (stripped)
            opt,                    # Flag de optimización (-O0, -O1, -O2, etc.)
            "-o", ruta_salida
        ]

        print(f"Compilando conjunto [{opt_tag}] (stripped): {NOMBRE_PROYECTO} -> {nombre_salida}")
        
        # Capturar TODO el flujo de salida en tiempo real (stdout y stderr combinados)
        resultado = subprocess.run(
            comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        estado = "ÉXITO" if resultado.returncode == 0 else "ERROR"
        print(f"   Resultado: {estado}")

        # Escribir la ficha completa de este ejecutable en el informe
        with open(ARCHIVO_INFORME, "a", encoding="utf-8") as f_informe:
            f_informe.write("=" * 80 + "\n")
            f_informe.write(f"ENTRADA: Proy. Conjunto ({len(archivos_c)} archivos .c) | SALIDA: {nombre_salida}\n")
            f_informe.write(f"ARCHIVOS INCLUIDOS: {', '.join(archivos_c)}\n")
            f_informe.write(f"HORA: {datetime.now().strftime('%H:%M:%S')} | TARGET: {target} | OPTIMIZACIÓN: {opt_tag}\n")
            f_informe.write(f"ESTADO: {estado} (Código de retorno: {resultado.returncode})\n")
            f_informe.write(f"COMANDO: {' '.join(comando)}\n")
            f_informe.write("-" * 80 + "\n")
            f_informe.write("SALIDA COMPLETA DE TERMINAL / DOCKER / GCC:\n")
            
            salida_terminal = resultado.stdout.strip()
            if salida_terminal:
                f_informe.write(salida_terminal + "\n")
            else:
                f_informe.write("[Sin mensajes en terminal - Compilación limpia]\n")
                
            f_informe.write("=" * 80 + "\n\n")

print("\n¡Proceso de compilación conjunta e informe completados!")
