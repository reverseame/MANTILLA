import os
import re
import sys
import io
from contextlib import redirect_stdout
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

# Intentar importar librerías gráficas para generar el heatmap
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False

# Importación nativa de MANTILLA
try:
    import MANTILLA
except ImportError:
    print("  Error: No se encontró 'MANTILLA.py'. Asegúrate de que esté en la misma carpeta.")
    sys.exit(1)


# ==========================================
# 1. FUNCIONES DE PROCESAMIENTO DE ETIQUETAS
# ==========================================
def normalizar_label(label: str) -> str:
    """Normaliza variantes de nomenclatura en las etiquetas."""
    if not label:
        return label
    
    tokens = re.split(r'([_-])', label)
    tokens_norm = ["glibc" if t.lower() == "gnu" else t for t in tokens]
    res = "".join(tokens_norm)
    
    return res.replace("x86-64", "x86").replace("x86_64", "x86")


def extraer_etiqueta_real(nombre_archivo: str) -> str:
    """Extrae la clase esperada limpiando la extensión del ejecutable."""
    nombre_sin_ext = os.path.splitext(nombre_archivo)[0]
    nombre = nombre_sin_ext.lower()
    
    arch = ""
    if "arm64" in nombre or "aarch64" in nombre: arch = "arm"
    elif "arm" in nombre: arch = "arm"
    elif "mips64" in nombre or "mips" in nombre: arch = "mips"
    elif "ppc" in nombre or "powerpc" in nombre: arch = "ppc"
    elif "sparc" in nombre: arch = "sparc"
    elif "x86_64" in nombre or "amd64" in nombre: arch = "x86-64"
    elif "x86" in nombre or "i686" in nombre: arch = "x86"
    
    libc = ""
    if "mingw" in nombre: libc = "mingw"
    elif "glibc" in nombre or "gnu" in nombre: libc = "glibc"
    elif "musl" in nombre: libc = "musl"
    elif "uclibc" in nombre: libc = "uclibc"
    
    if arch and libc:
        label = f"{arch}_{libc}_gcc"
    else:
        label = nombre_sin_ext.split('_')[0]
    
    return normalizar_label(label)


# ==========================================
# 2. EJECUCIÓN Y PARSEO DE MANTILLA
# ==========================================
def ejecutar_mantilla_nativamente(directorio: str, modelo_csv: str, k_vecinos: str, umbral: str) -> str:
    """Itera sobre la carpeta de binarios invocando MANTILLA con -b por cada archivo."""
    archivos = sorted([
        os.path.join(directorio, f) for f in os.listdir(directorio)
        if os.path.isfile(os.path.join(directorio, f))
    ])

    buffer_salida = io.StringIO()

    for ruta_archivo in archivos:
        # Omite archivos .json si existen en la carpeta
        if ruta_archivo.lower().endswith('.json'):
            continue

        sys.argv = [
            "MANTILLA.py",
            "-b", ruta_archivo,
            "-f", modelo_csv,
            "-k", str(k_vecinos),
            "-t", str(umbral)
        ]

        try:
            with redirect_stdout(buffer_salida):
                if hasattr(MANTILLA, 'main'):
                    MANTILLA.main()
        except Exception as e:
            buffer_salida.write(f"\nFile: {ruta_archivo}\nError analizando binario: {e}\n")

    return buffer_salida.getvalue()


def parsear_predicciones(salida_mantilla: str) -> tuple[list[dict], list[str], list[str]]:
    """Procesa el texto generado por MANTILLA para binarios."""
    lineas = salida_mantilla.strip().split("\n")
    resultados, y_reales, y_predichos = [], [], []
    archivo_actual = None

    for linea in lineas:
        linea_limpia = linea.strip()
        if not linea_limpia:
            continue
        
        match_file = re.search(r'^file:\s*(.+)', linea_limpia, re.IGNORECASE)
        if match_file:
            ruta_completa = match_file.group(1).strip()
            archivo_actual = os.path.basename(ruta_completa)
            continue
        
        match_pred = re.search(r'most common prediction:\s*([^\s\(]+)', linea_limpia, re.IGNORECASE)
        if match_pred and archivo_actual:
            prediccion_raw = match_pred.group(1).strip()
            
            # Quita extensiones si MANTILLA devuelve nombres de archivos en la predicción
            prediccion_base = os.path.splitext(os.path.basename(prediccion_raw))[0]
            prediccion = normalizar_label(prediccion_base)
            
            etiqueta_real = extraer_etiqueta_real(archivo_actual)
            es_correcto = (prediccion == etiqueta_real)
            
            resultados.append({
                'archivo': archivo_actual,
                'real': etiqueta_real,
                'predicho': prediccion,
                'correcto': es_correcto
            })
            y_reales.append(etiqueta_real)
            y_predichos.append(prediccion)
            
            archivo_actual = None

    if not resultados:
        print("Salida recibida de MANTILLA:\n")
        print(salida_mantilla)
        sys.exit(1)

    return resultados, y_reales, y_predichos


# ==========================================
# 3. MÉTRICAS, GRÁFICOS E INFORME
# ==========================================
def calcular_matriz_y_graficar(y_reales: list[str], y_predichos: list[str], archivo_imagen: str):
    """Genera la matriz de confusión, extrae desgloses de error y guarda el Heatmap PNG."""
    etiquetas_unicas = sorted(list(set(y_reales + y_predichos)))
    matriz_conf = confusion_matrix(y_reales, y_predichos, labels=etiquetas_unicas)

    errores = []
    for i, real in enumerate(etiquetas_unicas):
        for j, pred in enumerate(etiquetas_unicas):
            cantidad = matriz_conf[i, j]
            if i != j and cantidad > 0:
                errores.append({'Clase Real': real, 'Clasificado como (Predicho)': pred, 'Frecuencia': cantidad})
    df_errores = pd.DataFrame(errores)

    if HAS_PLOT:
        plt.figure(figsize=(10, 8))
        sns.heatmap(matriz_conf, annot=True, fmt='d', cmap='Blues',
                    xticklabels=etiquetas_unicas, yticklabels=etiquetas_unicas)
        plt.xlabel('Predicción MANTILLA', fontsize=11, fontweight='bold')
        plt.ylabel('Etiqueta Real Esperada', fontsize=11, fontweight='bold')
        plt.title('Matriz de Confusión - Evaluación de Binarios', fontsize=13, fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        plt.tight_layout()
        plt.savefig(archivo_imagen, dpi=300)
        plt.close()

    return etiquetas_unicas, matriz_conf, df_errores


def generar_informe_markdown(resultados, y_reales, y_predichos, etiquetas_unicas, 
                             matriz_conf, df_errores, salida_mantilla, config, 
                             archivo_informe, archivo_imagen) -> tuple[int, int, float]:
    """Construye y guarda el informe en formato Markdown."""
    df_res = pd.DataFrame(resultados)
    total = len(df_res)
    aciertos = df_res['correcto'].sum()
    accuracy = (aciertos / total) * 100 if total > 0 else 0
    headers_indices = [f"[{i+1}]" for i in range(len(etiquetas_unicas))]

    informe = [
        "#  Informe de Evaluación de Binarios MANTILLA (`-b` en Lote)\n",
        f"- **Directorio analizado:** `{config['directorio']}`",
        f"- **Total de binarios procesados:** {total}",
        f"- **Binarios clasificados correctamente:** {aciertos}",
        f"- **Precisión Global (Accuracy):** **{accuracy:.2f}%**",
        f"- **Configuración:** $k={config['k_vecinos']}$, umbral $d \\le {config['umbral']}$\n",
        "## Clasificación Completa por Métrica\n",
        "```text",
        classification_report(y_reales, y_predichos, zero_division=0),
        "```\n"
    ]

    if HAS_PLOT:
        informe.append("## Mapa de Calor de Confusión\n")
        informe.append(f"![Matriz de Confusión]({archivo_imagen})\n")

    informe.append("## Matriz de Confusión (Vista Compacta)\n")
    informe.append("*(Las columnas usan índices `[1]` a `[N]`. El símbolo `·` representa cero errores)*\n")

    md_matrix = [
        "| Clase Real \\ Predicciones | " + " | ".join(headers_indices) + " |",
        "| :--- | " + " | ".join(["---:"] * len(headers_indices)) + " |"
    ]

    for i, row in enumerate(matriz_conf):
        row_cells = []
        for j, val in enumerate(row):
            if val == 0:
                row_cells.append("·")
            elif i == j:
                row_cells.append(f"**{val}**")
            else:
                row_cells.append(f"`{val}`")
        md_matrix.append(f"| **{headers_indices[i]}** `{etiquetas_unicas[i]}` | " + " | ".join(row_cells) + " |")

    informe.append("\n".join(md_matrix))
    informe.append("\n**Leyenda de Clases (Columnas):**\n")
    for idx, label in zip(headers_indices, etiquetas_unicas):
        informe.append(f"- **{idx}**: `{label}`")

    informe.append("\n### Desglose Exclusivo de Confusiones / Errores\n")
    if not df_errores.empty:
        informe.append("| Clase Real | Clasificado Erróneamente Como | Nº de Archivos |")
        informe.append("| :--- | :--- | :---: |")
        for _, err in df_errores.iterrows():
            informe.append(f"| `{err['Clase Real']}` | `{err['Clasificado como (Predicho)']}` | **{err['Frecuencia']}** |")
    else:
        informe.append("  **¡No se registraron errores de clasificación!**\n")

    informe.append("\n##  Resultados Individuales por Archivo Binario\n")
    informe.append("| Ejecutable | Etiqueta Esperada | Predicción MANTILLA | Estado |")
    informe.append("| :--- | :--- | :--- | :--- |")

    for _, r in df_res.iterrows():
        estado = "   Correcto" if r['correcto'] else "  Error"
        informe.append(f"| `{r['archivo']}` | **{r['real']}** | {r['predicho']} | {estado} |")

    informe.append("\n## Anexo: Salida Cruda de MANTILLA\n")
    informe.append("```text")
    informe.append(salida_mantilla.strip())
    informe.append("```")

    with open(archivo_informe, "w", encoding="utf-8") as f:
        f.write("\n".join(informe))

    return total, aciertos, accuracy


# ==========================================
# 4. ORQUESTADOR PRINCIPAL
# ==========================================
def evaluar_mantilla():
    """Función principal que coordina la evaluación sobre binarios."""
    config = {
        'directorio': "./Bin",
        'modelo_csv': "features_model.csv",
        'k_vecinos': "5",
        'umbral': "0.1"
    }
    archivo_informe = "informe_mantilla_binarios.md"
    archivo_imagen = "matriz_confusion_binarios.png"

    salida_mantilla = ejecutar_mantilla_nativamente(
        config['directorio'], config['modelo_csv'], config['k_vecinos'], config['umbral']
    )

    resultados, y_reales, y_predichos = parsear_predicciones(salida_mantilla)

    etiquetas_unicas, matriz_conf, df_errores = calcular_matriz_y_graficar(
        y_reales, y_predichos, archivo_imagen
    )

    generar_informe_markdown(
        resultados, y_reales, y_predichos, etiquetas_unicas, matriz_conf,
        df_errores, salida_mantilla, config, archivo_informe, archivo_imagen
    )

if __name__ == "__main__":
    evaluar_mantilla()
