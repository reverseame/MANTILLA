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
CARPETA_ORIGEN = "./C_2"            # Archivos .c NUEVOS
CARPETA_DESTINO = "./salida"        # Carpeta para ejecutables stripped
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

archivos_c = [f for f in os.listdir(CARPETA_ORIGEN) if f.endswith('.c')]

if not archivos_c:
    print(f"No se encontraron archivos .c en '{CARPETA_ORIGEN}'")
    exit(1)

# Inicializar cabecera principal del archivo de informe
with open(ARCHIVO_INFORME, "w", encoding="utf-8") as f_informe:
    f_informe.write("=" * 80 + "\n")
    f_informe.write("           INFORME DETALLADO DE COMPILACIÓN DE MANTILLA           \n")
    f_informe.write(f"Fecha de inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f_informe.write(f"Total de fuentes C a procesar: {len(archivos_c)}\n")
    f_informe.write(f"Total de targets: {len(TARGETS)}\n")
    f_informe.write(f"Niveles de optimización: {', '.join(OPTIMIZACIONES)}\n")
    f_informe.write("=" * 80 + "\n\n")

# Bucle principal por Target
for target in TARGETS:
    for opt in OPTIMIZACIONES:
        opt_tag = opt.replace("-", "")
        
        for archivo in archivos_c:
            nombre_sin_extension = os.path.splitext(archivo)[0]
            extension = ".exe" if "mingw32" in target else ""
            
            nombre_salida = f"{target}_{opt_tag}_{nombre_sin_extension}{extension}"
            ruta_salida = os.path.join(CARPETA_DESTINO, nombre_salida)
            ruta_entrada = os.path.join(CARPETA_ORIGEN, archivo)
            
            comando = [
                "xcross",
                f"--target={target}",
                "gcc",
                opt,
                "-s",
                ruta_entrada,
                "-o", ruta_salida
            ]

            print(f"Compilando [{opt_tag}] (stripped): {archivo} -> {nombre_salida}")
            
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
                f_informe.write(f"ENTRADA: {archivo} | SALIDA: {nombre_salida}\n")
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
