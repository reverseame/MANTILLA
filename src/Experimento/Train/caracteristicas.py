import json
from pathlib import Path
import pandas as pd

try:
    from MANTILLA import get_feature_dict
except ImportError:
    raise ImportError(
        "No se encontró 'MANTILLA.py'. Asegúrate de que esté en el mismo directorio."
    )


def derive_label(file_name: str) -> str:
    """Identifica la arquitectura y entorno C a partir del nombre del ejecutable.

    Devuelve la etiqueta correspondiente (ej. 'x86_glibc_gcc').
    """
    fn = file_name.lower()

    # 1. Deducción de arquitectura
    arch_map = ["x86", "arm64", "mips", "ppc", "sparc"]
    arch = next(("arm" if a == "arm64" else a for a in arch_map if a in fn), None)

    # 2. Deducción de librería / runtime C
    libc_map = [("musl", "musl"), ("gnu", "glibc"), ("uclibc", "uclibc"), ("mingw32", "mingw")]
    libc = next((val for key, val in libc_map if key in fn), None)

    if arch and libc:
        return f"{arch}_{libc}_gcc"
    
    return "unknown"


def extract_features_from_json(json_path: Path) -> list[dict]:
    """Lee un fichero JSON individual, procesa sus funciones utilizando MANTILLA

    y les asigna la etiqueta deducida.
    """
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f" Error al leer el archivo {json_path.name}: {e}")
        return []

    # Extraer el nombre del binario original y derivar la etiqueta
    binary_name = data.get("file", {}).get("file_name", "")
    label = derive_label(binary_name)

    records = []
    for key, val in data.items():
        # Ignorar el bloque de metadatos 'file'
        if key != "file" and isinstance(val, dict):
            row = get_feature_dict(val)              
            row["label"] = label
            records.append(row)

    return records


def save_dataframe_to_csv(df: pd.DataFrame, output_csv: str) -> None:
    """Guarda o anexa un DataFrame en el fichero CSV especificado."""
    if df.empty or not output_csv:
        print("No se generaron registros para guardar.")
        return

    csv_path = Path(output_csv)
    exists = csv_path.exists()

    df.to_csv(
        csv_path,
        mode="a" if exists else "w",
        header=not exists,
        index=False,
    )

    estado = "añadidos a" if exists else "guardados en"
    print(f" ¡Éxito! Datos {estado}: '{output_csv}' ({len(df)} muestras procesadas).")


def process_directory(dir_path: str, output_csv: str = "features_model.csv") -> pd.DataFrame:
    """Recorre la carpeta de JSONs, procesa cada archivo

    y exporta los resultados acumulados a CSV.
    """
    all_records = []
    json_files = list(Path(dir_path).glob("*.json"))

    for json_file in json_files:
        features = extract_features_from_json(json_file)
        all_records.extend(features)

    df_result = pd.DataFrame(all_records)
    save_dataframe_to_csv(df_result, output_csv)

    return df_result

if __name__ == "__main__":
    PATH_JSONS = "./Prueba"
    CSV_SALIDA = "features_model.csv"

    df_final = process_directory(PATH_JSONS, CSV_SALIDA)

