#  Informe de Evaluación de Binarios MANTILLA

- **Total de binarios procesados:** 2745
- **Binarios clasificados correctamente:** 2615
- **Precisión Global (Accuracy):** **95.26%**
- **Configuración:** $k=5$, umbral $d = 0.1$

## Clasificación Completa por Métrica

```text
                  precision    recall  f1-score   support

   arm_glibc_gcc       1.00      1.00      1.00       100
    arm_musl_gcc       0.77      0.61      0.68       109
  arm_uclibc_gcc       0.91      0.95      0.93       437
  mips_glibc_gcc       0.69      1.00      0.82        82
   mips_musl_gcc       1.00      1.00      1.00        64
 mips_uclibc_gcc       1.00      0.92      0.96       467
   ppc_glibc_gcc       1.00      1.00      1.00       161
    ppc_musl_gcc       0.83      1.00      0.91       148
  ppc_uclibc_gcc       1.00      0.93      0.97       470
 sparc_glibc_gcc       1.00      1.00      1.00       165
sparc_uclibc_gcc       1.00      1.00      1.00       497
   x86_mingw_gcc       1.00      1.00      1.00        45

        accuracy                           0.95      2745
       macro avg       0.93      0.95      0.94      2745
    weighted avg       0.96      0.95      0.95      2745

```

## Matriz de Confusión (Vista Compacta)


| Clase Real \ Predicciones | [1] | [2] | [3] | [4] | [5] | [6] | [7] | [8] | [9] | [10] | [11] | [12] |
| **[1]** `arm_glibc_gcc`   | 100 | ·   | ·   | ·   | ·   | ·   | ·   | ·   | ·   | ·    | ·    | ·    |
| **[2]** `arm_musl_gcc`    | ·   | 66  |  43 | ·   | ·   | ·   | ·   | ·   | ·   | ·    | ·    | ·    |
| **[3]** `arm_uclibc_gcc`  | ·   | 20  | 417 | ·   | ·   | ·   | ·   | ·   | ·   | ·    | ·    | ·    |
| **[4]** `mips_glibc_gcc`  | ·   | ·   | ·   | 82  | ·   | ·   | ·   | ·   | ·   | ·    | ·    | ·    |
| **[5]** `mips_musl_gcc`   | ·   | ·   | ·   | ·   | 64  | ·   | ·   | ·   | ·   | ·    | ·    | ·    |
| **[6]** `mips_uclibc_gcc` | ·   | ·   | ·   | 36  | ·   | 431 | ·   | ·   | ·   | ·    | ·    | ·    |
| **[7]** `ppc_glibc_gcc`   | ·   | ·   | ·   | ·   | ·   | ·   | 161 | ·   | ·   | ·    | ·    | ·    |
| **[8]** `ppc_musl_gcc`    | ·   | ·   | ·   | ·   | ·   | ·   | ·   | 148 | ·   | ·    | ·    | ·    |
| **[9]** `ppc_uclibc_gcc`  | ·   | ·   | ·   | ·   | ·   | ·   | ·   | 31  | 439 | ·    | ·    | ·    |
| **[10]** `sparc_glibc_gcc`| ·   | ·   | ·   | ·   | ·   | ·   | ·   | ·   | ·   | 165  | ·    | ·    |
| **[11]**`sparc_uclibc_gcc`| ·   | ·   | ·   | ·   | ·   | ·   | ·   | ·   | ·   | ·    | 497  | ·    |
| **[12]** `x86_mingw_gcc`  | ·   | ·   | ·   | ·   | ·   | ·   | ·   | ·   | ·   | ·    | ·    | 45   |


### Desglose Exclusivo de Confusiones / Errores

| Clase Real        | Clasificado Erróneamente Como | Nº de Archivos |
| `arm_musl_gcc`    | `arm_uclibc_gcc`              | **43**         |
| `arm_uclibc_gcc`  | `arm_musl_gcc`                | **20**         |
| `mips_uclibc_gcc` | `mips_glibc_gcc`              | **36**         |
| `ppc_uclibc_gcc`  | `ppc_musl_gcc`                | **31**         |

##  Resultados Individuales por Archivo Binario

| Ejecutable | Etiqueta Esperada | Predicción MANTILLA | Estado |
| :--- | :--- | :--- | :--- |
| `arm64-unknown-linux-gnu_O0_Fud-Bypass.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_Linux.Dataseg.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_Lizzard Stresser.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_Prometheus v4.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_TriGemini.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_bashdoor.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_bluenurse.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_client_1.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_client_16.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_client_LizzardSquad.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_client_lulz.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_client_reaper.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_client_selfrep.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_client_void.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_godlyhttp.c_[qbot_client]_lulz.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_hide-_19.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_hide_19.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_jimmy-sfe.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_randomware.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O0_server_16.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_Fud-Bypass.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_Linux.Dataseg.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_Lizzard Stresser.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_Prometheus v4.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_TriGemini.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_bashdoor.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_bluenurse.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_client_1.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_client_16.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_client_LizzardSquad.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_client_lulz.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_client_reaper.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_client_selfrep.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_client_void.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_godlyhttp.c_[qbot_client]_lulz.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_hide-_19.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_hide_19.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_jimmy-sfe.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_ranzou-sfe.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O1_server_16.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_Fud-Bypass.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_Linux.Dataseg.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_Lizzard Stresser.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_Prometheus v4.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_TriGemini.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_bashdoor.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_bluenurse.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_client_1.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_client_16.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_client_LizzardSquad.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_client_lulz.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_client_reaper.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_client_selfrep.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_client_void.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_godlyhttp.c_[qbot_client]_lulz.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_hide-_19.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_hide_19.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_jimmy-sfe.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_ranzou-sfe.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O2_server_16.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_Fud-Bypass.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_Linux.Dataseg.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_Lizzard Stresser.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_Prometheus v4.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_TriGemini.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_bashdoor.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_bluenurse.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_client_1.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_client_16.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_client_LizzardSquad.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_client_lulz.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_client_reaper.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_client_selfrep.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_client_void.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_godlyhttp.c_[qbot_client]_lulz.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_hide-_19.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_hide_19.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_jimmy-sfe.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_ranzou-sfe.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_O3_server_16.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_Fud-Bypass.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_Linux.Dataseg.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_Lizzard Stresser.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_Prometheus v4.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_TriGemini.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_bashdoor.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_bluenurse.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_client_1.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_client_16.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_client_LizzardSquad.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_client_lulz.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_client_reaper.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_client_selfrep.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_client_void.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_godlyhttp.c_[qbot_client]_lulz.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_hide-_19.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_hide_19.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_jimmy-sfe.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_ranzou-sfe.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-gnu_Os_server_16.json` | **arm_glibc_gcc** | arm_glibc_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_Linux.Dataseg.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_Massacre.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_SeCshell.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_TriGemini.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_bashdoor.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_client_lulz.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O0_cnc_13.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O0_hide-_19.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O0_hide_19.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_jimmy-sfe.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_kaiten.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O0_programa_15.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O0_programa_17.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_randomware.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O0_reaper_reaper.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O0_server.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_server_1.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_server_16.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O0_server_LizzardSquad.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_server_void.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O0_start_void.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_Linux.Dataseg.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O1_Massacre.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O1_SeCshell.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_TriGemini.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_bashdoor.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_client_lulz.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O1_cnc_13.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_hide-_19.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O1_hide_19.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_jimmy-sfe.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_kaiten.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_programa_15.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_programa_17.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O1_randomware.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O1_ranzou-sfe.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O1_reaper_reaper.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O1_server.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_server_1.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_server_16.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_server_LizzardSquad.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_server_void.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O1_start_void.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O2_Linux.Dataseg.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_Massacre.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_SeCshell.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_TriGemini.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_bashdoor.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_client_lulz.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O2_cnc_13.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O2_hide-_19.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O2_hide_19.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_jimmy-sfe.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_kaiten.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O2_programa_15.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_programa_17.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_randomware.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_ranzou-sfe.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O2_reaper_reaper.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O2_server.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_server_1.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_server_16.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_server_LizzardSquad.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_server_void.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O2_start_void.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_Linux.Dataseg.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_Massacre.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_SeCshell.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_TriGemini.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_bashdoor.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_client_lulz.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O3_cnc_13.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O3_hide-_19.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O3_hide_19.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_jimmy-sfe.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_kaiten.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O3_programa_15.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O3_programa_17.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_randomware.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_ranzou-sfe.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O3_reaper_reaper.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O3_server.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_server_1.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_server_16.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_server_LizzardSquad.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_O3_server_void.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_O3_start_void.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_Os_Linux.Dataseg.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_Os_Massacre.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_Os_SeCshell.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_TriGemini.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_Os_bashdoor.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_client_lulz.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_cnc_13.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_hide-_19.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_hide_19.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_jimmy-sfe.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_Os_kaiten.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_programa_15.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_Os_programa_17.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_randomware.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_ranzou-sfe.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_reaper_reaper.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_server.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_Os_server_1.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_Os_server_16.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_Os_server_LizzardSquad.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-musl_Os_server_void.json` | **arm_musl_gcc** | arm_uclibc_gcc |   Error |
| `arm64-unknown-linux-musl_Os_start_void.json` | **arm_musl_gcc** | arm_musl_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_CFuck1.2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_Chargen.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_DDoS1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_DDoS2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_DDoS3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_DOMINATE.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_Fud-Bypass.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_Heartbeat.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_Improved SSYN.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_Linux.Dataseg.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_Lizzard Stresser.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_Massacre.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_Netbios.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_Prometheus v4.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_Quake.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_SSDP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_STCP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_SeCshell.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_TriGemini.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_bashdoor.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_bluenurse.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_bot_13.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_client.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_client_1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_client_16.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_client_LizzardSquad.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_client_lulz.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_client_reaper.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_client_selfrep.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_client_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_cnc_13.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_enemy.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_essyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_godlyhttp.c_[qbot_client]_lulz.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_hide.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_hide-_19.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_hide_19.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_jimmy-sfe.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_juno.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_kaiten.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_mDNS.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_oreo.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_oudp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_programa_15.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_programa_17.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_randomware.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_reaper_reaper.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_server.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_server_1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_server_16.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_server_LizzardSquad.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_server_selfrep.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_server_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_start_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_telnet.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O0_yummy.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_CFuck1.2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Chargen.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_DDoS1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_DDoS2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_DDoS3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_DOMINATE.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_EQUINOX.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_EvilESP1-1.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O1_EvilESPV3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Fud-Bypass.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Heartbeat.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Improved SSYN.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_KILLALLv2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Linux.Dataseg.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Lizzard Stresser.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Massacre.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Netbios.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_OVH-VIP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Prometheus v4.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Quake.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_SSDP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_SSYN2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_STCP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_SeCshell.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_Syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_TCP-GEN.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_TS3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_TriGemini.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_UDP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_UFWSIv4.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_bashdoor.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_bluenurse.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_bot_13.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_brrr.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_client.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_client_1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_client_16.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_client_LizzardSquad.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_client_lulz.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_client_reaper.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_client_selfrep.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_client_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_cnc_13.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_csyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_enemy.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_fivemovh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_flux.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_game.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_godlyhttp.c_[qbot_client]_lulz.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_hide.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_hide-_19.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_hide_19.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_jimmy-sfe.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_kaiten.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_mDNS.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_nova.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_oackv1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_oreo.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_oudp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_programa_15.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_programa_17.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_randomware.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_ranzou-sfe.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_reaper_reaper.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_rssyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_server.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O1_server_1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_server_16.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_server_LizzardSquad.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_server_selfrep.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_server_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_start_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_stcp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_sybexv3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_synopts.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_tcp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_tcp-synack.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_tcp_ack.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_tcp_psh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_tcp_syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_tcpabuse.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_udpbypass.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_udprand.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_urg.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_werrraaa.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_xmas.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_xsyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_yummy.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O1_zsyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_50x.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_CFuck1.2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_Chargen.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_DDoS1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_DDoS2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_DDoS3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_DOMINATE.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_EQUINOX.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_EvilESP1-1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_EvilESPV3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_Fud-Bypass.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_GHP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_Heartbeat.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_Improved SSYN.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_KILLALLv2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_Linux.Dataseg.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O2_Lizzard Stresser.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_Massacre.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_Netbios.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_OVH-VIP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_Prometheus v4.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_Quake.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_SSDP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_STCP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_SeCshell.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_Syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_TCP-GEN.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_TS3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_TS3-VOXILITY.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_TriGemini.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_UDP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_UFWSIv4.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_ack.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_bashdoor.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_bluenurse.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_bot.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_bot_13.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_brrr.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_client.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_client_1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_client_16.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_client_LizzardSquad.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_client_lulz.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_client_reaper.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_client_selfrep.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_client_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_cnc.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_cnc_13.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_enemy.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O2_fin.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_fivemovh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_flux.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_frag.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_godlyhttp.c_[qbot_client]_lulz.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_hide.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_hide-_19.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_hide_19.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_issyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_jimmy-sfe.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_kaiten.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O2_kgb.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_mDNS.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_mixamp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_nova.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_oackv1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_oreo.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_oudp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_programa_15.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_programa_17.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_psh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_randomware.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_ranzou-sfe.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_reaper_reaper.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_rst.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_server.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_server_1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_server_16.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_server_LizzardSquad.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_server_selfrep.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_server_void.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O2_start_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_sybexv3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_synopts.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_tcp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_tcp-synack.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_tcp_ack.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_tcp_psh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_tcp_syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_tcpabuse.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_udpbypass.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_urg.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_werrraaa.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_xmas.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O2_yummy.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_50x.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_CFuck1.2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_Chargen.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_DDoS1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_DDoS2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_DDoS3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_DOMINATE.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_EQUINOX.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_EvilESP1-1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_EvilESPV3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_Fud-Bypass.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_GHP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_Heartbeat.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_Improved SSYN.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_KILLALLv2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_Linux.Dataseg.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O3_Lizzard Stresser.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_Massacre.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_Netbios.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_OVH-VIP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_Prometheus v4.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_Quake.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_SSDP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_STCP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_SeCshell.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_Syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_TCP-GEN.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_TS3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_TS3-VOXILITY.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O3_TriGemini.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_UDP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_UFWSIv4.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_amptfo.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_atcp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_bashdoor.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_bluenurse.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_bot.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O3_bot_13.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_client.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_client_1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_client_16.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O3_client_LizzardSquad.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_client_lulz.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_client_reaper.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_client_selfrep.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_client_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_cnc.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_cnc_13.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_enemy.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_fin.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_fivemovh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_flux.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O3_godlyhttp.c_[qbot_client]_lulz.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_hide.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_hide-_19.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_hide_19.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_imperium.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_issyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_jimmy-sfe.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_kaiten.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_kgb.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_mDNS.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_nova.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_oackv1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_oreo.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_oudp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_programa_15.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_programa_17.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O3_psh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_randomware.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_ranzou-sfe.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_rawudp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_reaper_reaper.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_rst.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_server.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O3_server_1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_server_16.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_server_LizzardSquad.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_O3_server_selfrep.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_server_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_start_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_sybexv3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_synopts.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_tcp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_tcp-synack.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_tcp_ack.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_tcp_psh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_tcp_syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_udpbypass.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_urg.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_xmas.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_O3_yummy.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_50x.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_CFuck1.2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_Chargen.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_DDoS1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_DDoS2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_DDoS3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_DOMINATE.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_EQUINOX.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_EvilESP1-1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_EvilESPV3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_Fud-Bypass.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_GHP.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_Os_Heartbeat.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_Improved SSYN.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_KILLALLv2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_Linux.Dataseg.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_Lizzard Stresser.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_Massacre.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_Netbios.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_OVH-VIP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_Prometheus v4.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_Quake.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_SSDP.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_Os_STCP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_SeCshell.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_Syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_TCP-GEN.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_TS3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_TS3-VOXILITY.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_TriGemini.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_UDP.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_UFWSIv4.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_atcp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_bashdoor.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_bluenurse.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_bogus.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_bot.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_bot_13.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_Os_brrr.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_client.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_client_1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_client_16.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_client_LizzardSquad.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_client_lulz.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_client_reaper.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_client_selfrep.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_client_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_cnc.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_cnc_13.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_csyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_enemy.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_fin.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_fivemovh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_flux.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_game.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_godlyhttp.c_[qbot_client]_lulz.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_grev2.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_hide.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_hide-_19.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_hide_19.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_issyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_jimmy-sfe.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_juno.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_kaiten.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_Os_kgb.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_mDNS.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_mixamp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_nova.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_oackv1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_oreo.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_oudp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_programa_15.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_programa_17.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_psh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_randomware.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_ranzou-sfe.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_reaper_reaper.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_rssyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_rst.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_server.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_server_1.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_server_16.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_server_LizzardSquad.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_server_selfrep.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_Os_server_void.json` | **arm_uclibc_gcc** | arm_musl_gcc |   Error |
| `arm64-unknown-linux-uclibc_Os_start_void.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_stcp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_sybexv3.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_synopts.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_tcp.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_tcp-synack.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_tcp_ack.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_tcp_psh.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_tcp_syn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_tcpabuse.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_udpbypass.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_urg.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_werrraaa.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_xmas.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_xsyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_yummy.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `arm64-unknown-linux-uclibc_Os_zsyn.json` | **arm_uclibc_gcc** | arm_uclibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O0_Linux.Dataseg.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O0_Lizzard Stresser.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O0_Prometheus v4.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O0_client_LizzardSquad.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O0_client_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O0_client_reaper.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O0_client_selfrep.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O0_client_void.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O0_godlyhttp.c_[qbot_client]_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O1_Linux.Dataseg.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O1_Lizzard Stresser.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O1_Prometheus v4.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O1_client_LizzardSquad.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O1_client_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O1_client_reaper.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O1_client_selfrep.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O1_client_void.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O1_godlyhttp.c_[qbot_client]_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O2_Linux.Dataseg.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O2_Lizzard Stresser.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O2_Prometheus v4.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O2_client_LizzardSquad.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O2_client_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O2_client_reaper.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O2_client_selfrep.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O2_client_void.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O2_godlyhttp.c_[qbot_client]_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O3_Linux.Dataseg.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O3_Lizzard Stresser.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O3_Prometheus v4.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O3_client_LizzardSquad.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O3_client_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O3_client_reaper.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O3_client_selfrep.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O3_client_void.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_O3_godlyhttp.c_[qbot_client]_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_Fud-Bypass.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_Linux.Dataseg.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_Lizzard Stresser.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_Prometheus v4.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_client_LizzardSquad.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_client_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_client_reaper.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_client_selfrep.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_client_void.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_godlyhttp.c_[qbot_client]_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-gnu_Os_ranzou-sfe.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_Linux.Dataseg.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_TriGemini.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_client_lulz.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_jimmy-sfe.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_programa_15.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_programa_17.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_randomware.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_reaper_reaper.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_server_16.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_server_LizzardSquad.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_server_void.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O0_start_void.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_Linux.Dataseg.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_TriGemini.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_client_lulz.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_jimmy-sfe.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_programa_15.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_programa_17.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_randomware.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_ranzou-sfe.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_reaper_reaper.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_server_16.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_server_LizzardSquad.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_server_void.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O1_start_void.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_Linux.Dataseg.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_TriGemini.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_client_lulz.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_jimmy-sfe.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_programa_15.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_programa_17.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_randomware.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_ranzou-sfe.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_reaper_reaper.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_server_16.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_server_LizzardSquad.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_server_void.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O2_start_void.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_Linux.Dataseg.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_TriGemini.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_client_lulz.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_jimmy-sfe.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_programa_15.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_programa_17.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_randomware.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_ranzou-sfe.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_reaper_reaper.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_server_16.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_server_LizzardSquad.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_server_void.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_O3_start_void.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_Linux.Dataseg.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_TriGemini.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_client_lulz.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_jimmy-sfe.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_programa_15.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_programa_17.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_randomware.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_ranzou-sfe.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_reaper_reaper.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_server_16.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_server_LizzardSquad.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_server_void.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips-unknown-linux-musl_Os_start_void.json` | **mips_musl_gcc** | mips_musl_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O0_Linux.Dataseg.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O0_Lizzard Stresser.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O0_Prometheus v4.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O0_client_LizzardSquad.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O0_client_reaper.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O0_client_selfrep.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O0_godlyhttp.c_[qbot_client]_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O1_Linux.Dataseg.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O1_Lizzard Stresser.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O1_Prometheus v4.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O1_client_LizzardSquad.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O1_client_reaper.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O1_client_selfrep.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O1_godlyhttp.c_[qbot_client]_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O2_Linux.Dataseg.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O2_Lizzard Stresser.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O2_Prometheus v4.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O2_client_LizzardSquad.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O2_client_reaper.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O2_client_selfrep.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O2_godlyhttp.c_[qbot_client]_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O3_Linux.Dataseg.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O3_Lizzard Stresser.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O3_Prometheus v4.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O3_client_LizzardSquad.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O3_client_reaper.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O3_client_selfrep.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_O3_godlyhttp.c_[qbot_client]_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_Os_Linux.Dataseg.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_Os_Lizzard Stresser.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_Os_Prometheus v4.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_Os_client_LizzardSquad.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_Os_client_reaper.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_Os_client_selfrep.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-gnu_Os_godlyhttp.c_[qbot_client]_lulz.json` | **mips_glibc_gcc** | mips_glibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_CFuck1.2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_Chargen.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_DOMINATE.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_Fud-Bypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_Heartbeat.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_Improved SSYN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_KILLALLv2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_Linux.Dataseg.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_Lizzard Stresser.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_Massacre.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_Netbios.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_Prometheus v4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_SeCshell.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_TriGemini.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_bashdoor.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_bluenurse.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_client_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_client_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_client_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_client_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_client_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_client_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_client_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_godlyhttp.c_[qbot_client]_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_hide-_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_hide_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_jimmy-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_programa_15.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_programa_17.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_randomware.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_reaper_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_server_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_server_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_server_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_server_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_server_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_start_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O0_tcp_syn.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_CFuck1.2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_Chargen.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_DOMINATE.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_EQUINOX.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_EvilESP1-1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_EvilESPV3.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_Fud-Bypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_Heartbeat.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_Improved SSYN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_KILLALLv2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_Linux.Dataseg.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_Lizzard Stresser.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_Massacre.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_Netbios.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_OVH-VIP.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_Prometheus v4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_SeCshell.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_TCP-GEN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_TriGemini.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_UFWSIv4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_bashdoor.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_bluenurse.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_client_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_client_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_client_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_client_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_client_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_client_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_client_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_fivemovh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_godlyhttp.c_[qbot_client]_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_hide-_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_hide_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_jimmy-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_programa_15.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_programa_17.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_randomware.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_ranzou-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_reaper_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_server_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_server_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_server_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_server_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_server_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_start_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_sybexv3.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_synopts.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_tcp-synack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_tcp_ack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_tcp_psh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_tcp_syn.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O1_udpbypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_CFuck1.2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_Chargen.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_DOMINATE.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_EQUINOX.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_EvilESP1-1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_EvilESPV3.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_Fud-Bypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_Heartbeat.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_Improved SSYN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_KILLALLv2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_Linux.Dataseg.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_Lizzard Stresser.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_Massacre.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_Netbios.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_OVH-VIP.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_Prometheus v4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_SeCshell.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_TCP-GEN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_TriGemini.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_UFWSIv4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_bashdoor.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_bluenurse.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_client_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_client_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_client_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_client_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_client_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_client_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_client_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_fivemovh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_godlyhttp.c_[qbot_client]_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_hide-_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_hide_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_jimmy-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_programa_15.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_programa_17.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_randomware.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_ranzou-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_reaper_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_server_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_server_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_server_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_server_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_server_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_start_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_sybexv3.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_synopts.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_tcp-synack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_tcp_ack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_tcp_psh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_tcp_syn.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O2_udpbypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_CFuck1.2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_Chargen.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_DOMINATE.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_EQUINOX.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_EvilESP1-1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_EvilESPV3.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_Fud-Bypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_Heartbeat.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_Improved SSYN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_KILLALLv2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_Linux.Dataseg.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_Lizzard Stresser.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_Massacre.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_Netbios.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_OVH-VIP.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_Prometheus v4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_SeCshell.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_TCP-GEN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_TriGemini.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_UFWSIv4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_bashdoor.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_bluenurse.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_client_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_client_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_client_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_client_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_client_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_client_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_client_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_fivemovh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_godlyhttp.c_[qbot_client]_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_hide-_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_hide_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_jimmy-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_programa_15.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_programa_17.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_randomware.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_ranzou-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_reaper_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_server_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_server_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_server_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_server_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_server_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_start_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_sybexv3.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_synopts.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_tcp-synack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_tcp_ack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_tcp_psh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_tcp_syn.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_O3_udpbypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_CFuck1.2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_Chargen.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_DOMINATE.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_EQUINOX.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_EvilESP1-1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_EvilESPV3.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_Fud-Bypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_Heartbeat.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_Improved SSYN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_KILLALLv2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_Linux.Dataseg.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_Lizzard Stresser.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_Massacre.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_Netbios.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_OVH-VIP.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_Prometheus v4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_SeCshell.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_TCP-GEN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_TriGemini.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_UFWSIv4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_bashdoor.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_bluenurse.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_client_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_client_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_client_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_client_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_client_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_client_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_client_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_fivemovh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_godlyhttp.c_[qbot_client]_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_hide-_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_hide_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_jimmy-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_programa_15.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_programa_17.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_randomware.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_ranzou-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_reaper_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_server_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_server_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_server_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_server_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_server_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_start_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_sybexv3.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_synopts.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_tcp-synack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_tcp_ack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_tcp_psh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_tcp_syn.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn32_Os_udpbypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_CFuck1.2.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O0_Chargen.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O0_DOMINATE.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_Fud-Bypass.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O0_Heartbeat.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O0_Improved SSYN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_Linux.Dataseg.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_Lizzard Stresser.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_Netbios.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_Prometheus v4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_SeCshell.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_TriGemini.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_bashdoor.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_bluenurse.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_client_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_client_16.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O0_client_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_client_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_client_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_client_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_client_void.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O0_godlyhttp.c_[qbot_client]_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_hide-_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_hide_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_jimmy-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_programa_15.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_programa_17.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_randomware.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_ranzou-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_reaper_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_server_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_server_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_server_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_server_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_server_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O0_start_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_CFuck1.2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_Chargen.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_DOMINATE.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_Fud-Bypass.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O1_Heartbeat.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O1_Improved SSYN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_Linux.Dataseg.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_Lizzard Stresser.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_Netbios.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_OVH-VIP.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_Prometheus v4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_SeCshell.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_TriGemini.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_bashdoor.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_bluenurse.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O1_client_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_client_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_client_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_client_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_client_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_client_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_client_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_godlyhttp.c_[qbot_client]_lulz.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O1_hide-_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_hide_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_jimmy-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_programa_15.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O1_programa_17.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_randomware.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_ranzou-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_reaper_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_server_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_server_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_server_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_server_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_server_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_start_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_sybexv3.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O1_tcp-synack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_tcp_ack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_tcp_psh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_tcp_syn.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O1_udpbypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_CFuck1.2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_Chargen.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_DOMINATE.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_Fud-Bypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_Heartbeat.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_Improved SSYN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_Linux.Dataseg.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_Lizzard Stresser.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_Netbios.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O2_OVH-VIP.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_Prometheus v4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_SeCshell.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_TriGemini.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_bashdoor.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_bluenurse.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_client_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_client_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_client_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_client_lulz.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O2_client_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_client_selfrep.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O2_client_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_godlyhttp.c_[qbot_client]_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_hide-_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_hide_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_jimmy-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_programa_15.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_programa_17.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O2_randomware.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_ranzou-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_reaper_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_server_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_server_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_server_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_server_selfrep.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O2_server_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_start_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_sybexv3.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O2_tcp-synack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_tcp_ack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_tcp_psh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_tcp_syn.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O2_udpbypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_CFuck1.2.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O3_Chargen.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_DOMINATE.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_Fud-Bypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_Heartbeat.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O3_Improved SSYN.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O3_Linux.Dataseg.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_Lizzard Stresser.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_Massacre.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_Netbios.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O3_OVH-VIP.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_Prometheus v4.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_SeCshell.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_TriGemini.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_bashdoor.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_bluenurse.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_bot_13.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_client.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_client_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_client_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_client_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_client_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_client_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_client_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_client_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_cnc_13.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O3_godlyhttp.c_[qbot_client]_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_hide-_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_hide_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_jimmy-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_kaiten.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_oackv1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_programa_15.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_programa_17.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_O3_randomware.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_ranzou-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_reaper_reaper.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_server.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_server_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_server_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_server_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_server_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_server_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_start_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_sybexv3.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_tcp-synack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_tcp_ack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_tcp_psh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_tcp_syn.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_O3_udpbypass.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_CFuck1.2.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_Chargen.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_DOMINATE.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_Fud-Bypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_Heartbeat.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_Improved SSYN.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_Linux.Dataseg.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_Lizzard Stresser.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_Netbios.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_OVH-VIP.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_Prometheus v4.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_SeCshell.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_TriGemini.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_bashdoor.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_bluenurse.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_bot_13.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_client.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_client_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_client_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_client_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_client_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_client_reaper.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_client_selfrep.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_client_void.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_cnc_13.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_godlyhttp.c_[qbot_client]_lulz.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_hide-_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_hide_19.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_jimmy-sfe.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_kaiten.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_oackv1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_programa_15.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_programa_17.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_randomware.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_ranzou-sfe.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_reaper_reaper.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_server.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_server_1.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_server_16.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_server_LizzardSquad.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_server_selfrep.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_server_void.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_start_void.json` | **mips_uclibc_gcc** | mips_glibc_gcc |   Error |
| `mips64-unknown-linux-uclibcn64_Os_sybexv3.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_tcp-synack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_tcp_ack.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_tcp_psh.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_tcp_syn.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `mips64-unknown-linux-uclibcn64_Os_udpbypass.json` | **mips_uclibc_gcc** | mips_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_DDoS1.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_DDoS2.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_DDoS3.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_Fud-Bypass.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_Linux.Dataseg.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_Lizzard Stresser.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_Prometheus v4.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_TriGemini.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_bashdoor.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_bluenurse.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_bot.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_bot_13.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_client.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_client_1.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_client_16.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_client_LizzardSquad.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_client_lulz.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_client_reaper.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_client_selfrep.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_client_void.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_enemy.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_flux.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_godlyhttp.c_[qbot_client]_lulz.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_hide.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_hide-_19.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_hide_19.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_jimmy-sfe.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_kaiten.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_oreo.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_randomware.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_server_16.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O0_yummy.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_DDoS1.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_DDoS2.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_DDoS3.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_Fud-Bypass.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_Linux.Dataseg.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_Lizzard Stresser.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_Prometheus v4.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_TriGemini.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_bashdoor.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_bluenurse.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_bot.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_bot_13.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_client.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_client_1.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_client_16.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_client_LizzardSquad.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_client_lulz.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_client_reaper.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_client_selfrep.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_client_void.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_enemy.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_flux.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_godlyhttp.c_[qbot_client]_lulz.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_hide.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_hide-_19.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_hide_19.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_jimmy-sfe.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_kaiten.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_oreo.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_ranzou-sfe.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_server_16.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O1_yummy.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_DDoS1.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_DDoS2.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_DDoS3.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_Fud-Bypass.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_Linux(1).Dataseg.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_Linux.Dataseg.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_Lizzard Stresser.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_Prometheus v4.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_TriGemini.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_bashdoor.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_bluenurse.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_bot.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_bot_13.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_client.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_client_1.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_client_16.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_client_LizzardSquad.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_client_lulz.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_client_reaper.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_client_selfrep.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_client_void.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_enemy.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_flux.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_godlyhttp.c_[qbot_client]_lulz.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_hide.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_hide-_19.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_hide_19.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_jimmy-sfe.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_kaiten.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_oreo.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_ranzou-sfe.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_server_16.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O2_yummy.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_DDoS1.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_DDoS2.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_DDoS3.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_Fud-Bypass.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_Linux.Dataseg.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_Lizzard Stresser.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_Prometheus v4.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_TriGemini.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_bashdoor.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_bluenurse.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_bot.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_bot_13.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_client.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_client_1.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_client_16.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_client_LizzardSquad.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_client_lulz.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_client_reaper.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_client_selfrep.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_client_void.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_enemy.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_flux.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_godlyhttp.c_[qbot_client]_lulz.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_hide.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_hide-_19.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_hide_19.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_jimmy-sfe.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_kaiten.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_oreo.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_ranzou-sfe.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_server_16.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_O3_yummy.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_DDoS1.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_DDoS2.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_DDoS3.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_Fud-Bypass.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_Linux.Dataseg.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_Lizzard Stresser.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_Prometheus v4.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_TriGemini.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_bashdoor.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_bluenurse.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_bot.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_bot_13.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_client.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_client_1.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_client_16.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_client_LizzardSquad.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_client_lulz.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_client_reaper.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_client_selfrep.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_client_void.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_enemy.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_flux.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_godlyhttp.c_[qbot_client]_lulz.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_hide.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_hide-_19.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_hide_19.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_jimmy-sfe.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_kaiten.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_oreo.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_ranzou-sfe.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_server_16.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-gnu_Os_yummy.json` | **ppc_glibc_gcc** | ppc_glibc_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_DDoS1.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_DDoS3.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_Linux.Dataseg.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_Massacre.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_SeCshell.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_TriGemini.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_bashdoor.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_bot.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_c7.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_client_lulz.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_cnc.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_cnc_13.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_enemy.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_hide.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_hide-_19.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_hide_19.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_jimmy-sfe.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_kaiten.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_programa_15.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_programa_17.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_randomware.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_reaper_reaper.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_server.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_server_1.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_server_16.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_server_LizzardSquad.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_server_void.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O0_start_void.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_DDoS1.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_DDoS3.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_Linux.Dataseg.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_Massacre.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_SeCshell.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_TriGemini.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_bashdoor.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_bot.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_c7.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_client_lulz.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_cnc.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_cnc_13.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_enemy.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_hide.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_hide-_19.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_hide_19.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_jimmy-sfe.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_kaiten.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_programa_15.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_programa_17.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_randomware.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_ranzou-sfe.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_reaper_reaper.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_server.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_server_1.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_server_16.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_server_LizzardSquad.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_server_void.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O1_start_void.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_DDoS1.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_DDoS3.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_Linux.Dataseg.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_Massacre.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_SeCshell.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_TriGemini.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_bashdoor.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_bot.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_c7.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_client_lulz.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_cnc.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_cnc_13.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_enemy.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_hide.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_hide-_19.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_hide_19.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_jimmy-sfe.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_kaiten.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_programa_15.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_programa_17.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_randomware.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_ranzou-sfe.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_reaper_reaper.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_server.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_server_1.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_server_16.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_server_LizzardSquad.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_server_void.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O2_start_void.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_DDoS1.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_DDoS3.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_Linux.Dataseg.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_Massacre.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_SeCshell.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_TriGemini.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_bashdoor.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_bot.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_c7.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_client_lulz.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_cnc.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_cnc_13.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_enemy.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_hide.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_hide-_19.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_hide_19.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_jimmy-sfe.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_kaiten.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_programa_15.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_programa_17.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_randomware.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_ranzou-sfe.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_reaper_reaper.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_server.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_server_1.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_server_16.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_server_LizzardSquad.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_server_void.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_O3_start_void.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_DDoS1.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_DDoS3.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_GHP.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_Linux.Dataseg.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_Massacre.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_SeCshell.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_TriGemini.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_bashdoor.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_bot.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_c7.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_client_lulz.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_cnc.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_cnc_13.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_enemy.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_flux.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_hide.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_hide-_19.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_hide_19.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_jimmy-sfe.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_kaiten.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_programa_15.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_programa_17.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_randomware.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_ranzou-sfe.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_reaper_reaper.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_rudy.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_server.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_server_1.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_server_16.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_server_LizzardSquad.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_server_void.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_slow.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-musl_Os_start_void.json` | **ppc_musl_gcc** | ppc_musl_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_50x.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_CFuck1.2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Chargen.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_DDoS1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_DDoS2.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O0_DDoS3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_DOMINATE.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Fud-Bypass.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Heartbeat.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Improved SSYN.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Linux.Dataseg.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Lizzard Stresser.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Massacre.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Netbios.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Prometheus v4.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Quake.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_SSDP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_STCP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_SeCshell.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_Syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_TS3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_TriGemini.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_UDP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_UDP_Telnet.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O0_UFWSIv4.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_bashdoor.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_bluenurse.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_bot.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_bot_13.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_c7.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_client.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_client_1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_client_16.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_client_LizzardSquad.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_client_lulz.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_client_reaper.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_client_selfrep.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_client_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_cnc.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O0_cnc_13.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O0_enemy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_godlyhttp.c_[qbot_client]_lulz.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_grev2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_hide.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_hide-_19.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_hide_19.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_imperium.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_jimmy-sfe.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_kaiten.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_mDNS.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O0_oreo.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_programa_15.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_programa_17.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_randomware.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_reaper_reaper.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_server.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_server_1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_server_16.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_server_LizzardSquad.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_server_selfrep.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_server_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_start_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_tcp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O0_yummy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_50x.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_CFuck1.2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Chargen.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_DDoS1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_DDoS2.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_DDoS3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_DOMINATE.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_EQUINOX.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_EvilESP1-1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_EvilESPV3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Fud-Bypass.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Heartbeat.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Improved SSYN.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_KILLALLv2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Linux.Dataseg.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Lizzard Stresser.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Massacre.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Netbios.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_OVH-VIP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Prometheus v4.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Quake.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_SSDP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_STCP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_SeCshell.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_Syn.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_TCP-GEN.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_TS3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_TS3-VOXILITY.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_TriGemini.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_UDP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_UDP_VSE.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_UFWSIv4.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_ZAP.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_atcp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_bashdoor.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_bluenurse.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_bogus.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_bot.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_bot_13.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_brrr.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_c7.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_client.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_client_1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_client_16.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_client_LizzardSquad.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_client_lulz.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_client_reaper.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_client_selfrep.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_client_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_cnc.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_cnc_13.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_csyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_enemy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_essyn.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_fin.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_fivemovh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_flux.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_game.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_godlyhttp.c_[qbot_client]_lulz.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_grev2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_hide.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_hide-_19.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_hide_19.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_issyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_jimmy-sfe.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_kaiten.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_kgb.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_mDNS.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_mixamp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_nova.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_oackv1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_oreo.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_oudp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_programa_15.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_programa_17.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_psh.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_randomware.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_ranzou-sfe.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_reaper_reaper.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_rst.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_se.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_server.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_server_1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_server_16.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_server_LizzardSquad.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_server_selfrep.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_server_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_start_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_stcp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_sybexv3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_synfin.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_synopts.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_tcp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_tcp-synack.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_tcp_ack.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_tcp_psh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_tcp_syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_tcpabuse.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_udpbypass.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_urg.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_werrraaa.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_wizard.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_xmas.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O1_xsyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_yummy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O1_zsyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_50x.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_CFuck1.2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_Chargen.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_DDoS1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_DDoS2.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O2_DDoS3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_DOMINATE.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_EQUINOX.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_EvilESP1-1.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O2_EvilESPV3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_Fud-Bypass.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O2_Heartbeat.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_Improved SSYN.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_KILLALLv2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_Linux.Dataseg.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_Lizzard Stresser.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_Massacre.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_Netbios.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_OVH-VIP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_Prometheus v4.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_Quake.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_SSDP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_STCP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_SeCshell.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_Syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_TCP-GEN.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_TS3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_TS3-VOXILITY.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_TriGemini.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_UDP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_UFWSIv4.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_bashdoor.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_bluenurse.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_bot.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_bot_13.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_brrr.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_c7.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_client.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_client_1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_client_16.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_client_LizzardSquad.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_client_lulz.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_client_reaper.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_client_selfrep.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_client_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_cnc.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O2_cnc_13.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_enemy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_fin.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_fivemovh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_flux.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_godlyhttp.c_[qbot_client]_lulz.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_hide.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_hide-_19.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_hide_19.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_issyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_jimmy-sfe.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_kaiten.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_kgb.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_mDNS.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_mixamp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_nova.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_oackv1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_oreo.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_oudp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_programa_15.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_programa_17.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_psh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_randomware.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_ranzou-sfe.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_reaper_reaper.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_rst.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_server.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_server_1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_server_16.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_server_LizzardSquad.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_server_selfrep.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_server_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_start_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_sybexv3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_synopts.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_tcp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_tcp-synack.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_tcp_ack.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_tcp_psh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_tcp_syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_tcpabuse.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_udpbypass.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_urg.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_werrraaa.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_xmas.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_xsyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O2_yummy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_50x.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_CFuck1.2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_Chargen.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_DDoS1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_DDoS2.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O3_DDoS3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_DOMINATE.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_EQUINOX.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_EvilESP1-1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_EvilESPV3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_Fud-Bypass.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O3_Heartbeat.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_Improved SSYN.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_KILLALLv2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_Linux.Dataseg.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_Lizzard Stresser.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_Massacre.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_Netbios.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_OVH-VIP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_Prometheus v4.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_Quake.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_SSDP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_SSYN2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_STCP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_SeCshell.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_Syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_TCP-GEN.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_TS3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_TS3-VOXILITY.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_TriGemini.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_UDP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_UFWSIv4.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_ack.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_amptfo.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_bashdoor.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_bluenurse.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_bot.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_bot_13.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_brrr.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_c7.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_client.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_client_1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_client_16.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_client_LizzardSquad.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_client_lulz.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_client_reaper.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_client_selfrep.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_client_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_cnc.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O3_cnc_13.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_enemy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_essyn.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_O3_fin.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_fivemovh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_flux.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_godlyhttp.c_[qbot_client]_lulz.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_hide.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_hide-_19.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_hide_19.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_issyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_jimmy-sfe.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_kaiten.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_kgb.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_mDNS.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_nova.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_oackv1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_oreo.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_oudp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_programa_15.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_programa_17.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_psh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_randomware.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_ranzou-sfe.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_rawudp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_reaper_reaper.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_rst.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_server.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_server_1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_server_16.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_server_LizzardSquad.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_server_selfrep.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_server_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_start_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_sybexv3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_synopts.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_tcp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_tcp-synack.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_tcp_ack.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_tcp_psh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_tcp_syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_tcpabuse.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_udpbypass.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_udprand.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_urg.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_werrraaa.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_xmas.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_O3_yummy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_50x.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_CFuck1.2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Chargen.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_DDoS1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_DDoS2.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_Os_DDoS3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_DOMINATE.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_EQUINOX.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_EvilESP1-1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_EvilESPV3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Fud-Bypass.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_GHP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Heartbeat.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Improved SSYN.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_KILLALLv2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Linux.Dataseg.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Lizzard Stresser.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Massacre.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Netbios.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_OVH-VIP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Prometheus v4.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Quake.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_SSDP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_STCP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_SeCshell.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_Syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_TCP-GEN.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_TS3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_TS3-VOXILITY.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_TriGemini.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_UDP.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_UDP_Telnet.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_UFWSIv4.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_atcp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_bashdoor.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_bluenurse.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_bogus.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_bot.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_bot_13.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_brrr.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_c7.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_client.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_client_1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_client_16.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_client_LizzardSquad.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_client_lulz.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_client_reaper.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_client_selfrep.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_client_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_cnc.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_Os_cnc_13.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_csyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_enemy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_fin.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_fivemovh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_flux.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_game.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_godlyhttp.c_[qbot_client]_lulz.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_grev2.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_hide.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_hide-_19.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_hide_19.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_issyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_jimmy-sfe.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_kaiten.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_kgb.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_mDNS.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_mixamp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_nova.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_oackv1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_oreo.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_oudp.json` | **ppc_uclibc_gcc** | ppc_musl_gcc |   Error |
| `ppc-unknown-linux-uclibc_Os_programa_15.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_programa_17.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_psh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_randomware.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_ranzou-sfe.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_reaper_reaper.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_rst.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_rudy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_server.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_server_1.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_server_16.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_server_LizzardSquad.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_server_selfrep.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_server_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_slow.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_start_void.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_stcp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_sybexv3.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_synopts.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_tcp.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_tcp-synack.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_tcp_ack.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_tcp_psh.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_tcp_syn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_tcpabuse.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_telnet.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_udpbypass.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_urg.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_vse.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_werrraaa.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_xmas.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_xsyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_yummy.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `ppc-unknown-linux-uclibc_Os_zsyn.json` | **ppc_uclibc_gcc** | ppc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_CFuck1.2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Chargen.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_DDoS1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_DDoS2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_DDoS3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_DOMINATE.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_EQUINOX.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_EvilESPV3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Fud-Bypass.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Heartbeat.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Improved SSYN.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Linux.Dataseg.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Lizzard Stresser.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Massacre.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Netbios.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Prometheus v4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Quake.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_SSDP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_STCP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_SeCshell.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_Syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_TS3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_TriGemini.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_UDP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_atcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_bashdoor.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_bluenurse.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_bot.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_bot_13.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_c7.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_client.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_client_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_client_16.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_client_LizzardSquad.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_client_lulz.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_client_reaper.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_client_selfrep.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_client_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_cnc.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_cnc_13.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_enemy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_godlyhttp.c_[qbot_client]_lulz.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_hide.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_hide-_19.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_hide_19.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_jimmy-sfe.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_kaiten.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_mDNS.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_oreo.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_10.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_11.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_12.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_17.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_5.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_7.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_8.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_9.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_programa_9_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_randomware.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_reaper_reaper.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_rudy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_server.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_server_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_server_16.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_server_LizzardSquad.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_server_selfrep.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_server_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_start_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_tcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_tcp-synack.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O0_yummy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_50x.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_CFuck1.2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_Chargen.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_DDoS1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_DDoS2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_DDoS3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_DOMINATE.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_EQUINOX.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_EvilESP1-1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_EvilESPV3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_Fud-Bypass.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_GHP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_Improved SSYN.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_KILLALLv2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_Linux.Dataseg.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_Lizzard Stresser.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_Massacre.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_Netbios.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_OVH-VIP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_Prometheus v4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_Quake.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_SSDP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_STCP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_SeCshell.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_Syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_TCP-GEN.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_TS3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_TriGemini.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_UDP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_UFWSIv4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_atcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_bashdoor.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_bluenurse.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_bot.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_bot_13.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_c7.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_client.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_client_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_client_16.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_client_LizzardSquad.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_client_lulz.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_client_reaper.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_client_selfrep.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_client_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_cnc.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_cnc_13.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_csyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_enemy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_fin.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_fivemovh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_flux.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_game.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_godlyhttp.c_[qbot_client]_lulz.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_hide.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_hide-_19.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_hide_19.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_jimmy-sfe.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_kaiten.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_kgb.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_mDNS.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_nova.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_oackv1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_oreo.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_oudp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_10.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_11.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_12.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_17.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_5.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_7.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_8.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_9.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_programa_9_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_psh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_randomware.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_ranzou-sfe.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_reaper_reaper.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_rst.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_rudy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_server.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_server_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_server_16.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_server_LizzardSquad.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_server_selfrep.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_server_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_slow.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_start_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_stcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_sybexv3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_synopts.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_tcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_tcp-synack.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_tcp_ack.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_tcp_psh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_tcp_syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_udpbypass.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_urg.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_xmas.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_xsyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_yummy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O1_zsyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_50x.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_CFuck1.2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Chargen.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_DDoS1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_DDoS2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_DDoS3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_DOMINATE.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_EQUINOX.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_EvilESP1-1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_EvilESPV3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Fud-Bypass.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_GHP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Heartbeat.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Improved SSYN.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_KILLALLv2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Linux.Dataseg.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Lizzard Stresser.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Massacre.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Netbios.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_OVH-VIP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Prometheus v4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Quake.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_SSDP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_STCP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_SeCshell.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_Syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_TCP-GEN.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_TS3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_TriGemini.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_UDP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_UFWSIv4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_bashdoor.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_bluenurse.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_bot.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_bot_13.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_c7.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_client.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_client_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_client_16.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_client_LizzardSquad.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_client_lulz.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_client_reaper.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_client_selfrep.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_client_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_cnc.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_cnc_13.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_csyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_enemy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_fin.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_fivemovh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_flux.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_game.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_godlyhttp.c_[qbot_client]_lulz.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_hide.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_hide-_19.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_hide_19.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_issyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_jimmy-sfe.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_kaiten.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_kgb.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_mDNS.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_nova.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_oackv1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_oreo.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_oudp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_10.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_11.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_12.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_17.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_5.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_7.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_8.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_9.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_programa_9_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_psh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_randomware.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_ranzou-sfe.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_reaper_reaper.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_rst.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_rudy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_server.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_server_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_server_16.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_server_LizzardSquad.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_server_selfrep.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_server_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_slow.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_start_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_stcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_sybexv3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_synopts.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_tcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_tcp-synack.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_tcp_ack.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_tcp_psh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_tcp_syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_udpbypass.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_urg.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_xmas.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_xsyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_yummy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O2_zsyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_50x.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_CFuck1.2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Chargen.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_DDoS1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_DDoS2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_DDoS3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_DOMINATE.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_EQUINOX.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_EvilESP1-1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_EvilESPV3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Fud-Bypass.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_GHP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Heartbeat.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Improved SSYN.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_KILLALLv2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Linux.Dataseg.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Lizzard Stresser.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Massacre.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Netbios.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_OVH-VIP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Prometheus v4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Quake.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_SSDP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_STCP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_SeCshell.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_Syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_TCP-GEN.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_TS3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_TriGemini.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_UDP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_UFWSIv4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_bashdoor.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_bluenurse.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_bot.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_bot_13.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_c7.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_client.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_client_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_client_16.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_client_LizzardSquad.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_client_lulz.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_client_reaper.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_client_selfrep.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_client_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_cnc.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_cnc_13.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_csyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_enemy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_fin.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_fivemovh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_flux.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_game.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_godlyhttp.c_[qbot_client]_lulz.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_hide.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_hide-_19.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_hide_19.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_issyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_jimmy-sfe.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_kaiten.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_kgb.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_mDNS.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_nova.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_oackv1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_oreo.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_oudp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_10.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_11.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_12.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_17.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_5.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_7.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_8.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_9.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_programa_9_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_psh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_randomware.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_ranzou-sfe.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_reaper_reaper.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_rst.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_rudy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_server.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_server_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_server_16.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_server_LizzardSquad.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_server_selfrep.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_server_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_slow.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_start_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_stcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_sybexv3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_synopts.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_tcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_tcp-synack.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_tcp_ack.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_tcp_psh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_tcp_syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_udpbypass.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_urg.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_xmas.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_O3_yummy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_50x.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_CFuck1.2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Chargen.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_DDoS1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_DDoS2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_DDoS3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_DOMINATE.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_EQUINOX.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_EvilESP1-1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_EvilESPV3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Fud-Bypass.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_GHP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Heartbeat.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Improved SSYN.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_KILLALLv2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Linux.Dataseg.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Lizzard Stresser.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Massacre.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Netbios.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_OVH-VIP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Prometheus v4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Quake.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_SSDP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_STCP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_SeCshell.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_Syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_TCP-GEN.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_TS3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_TriGemini.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_UDP.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_UFWSIv4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_atcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_bashdoor.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_bluenurse.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_bogus.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_bot.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_bot_13.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_c7.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_client.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_client_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_client_16.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_client_LizzardSquad.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_client_lulz.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_client_reaper.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_client_selfrep.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_client_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_cnc.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_cnc_13.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_csyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_enemy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_fin.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_fivemovh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_flux.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_game.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_godlyhttp.c_[qbot_client]_lulz.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_hide.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_hide-_19.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_hide_19.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_issyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_jimmy-sfe.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_kaiten.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_kgb.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_mDNS.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_nova.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_oackv1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_oreo.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_oudp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_10.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_11.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_12.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_17.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_2.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_4.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_5.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_7.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_8.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_9.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_programa_9_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_psh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_randomware.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_ranzou-sfe.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_reaper_reaper.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_rst.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_rudy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_server.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_server_1.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_server_16.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_server_LizzardSquad.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_server_selfrep.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_server_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_slow.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_start_void.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_stcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_sybexv3.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_synopts.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_tcp.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_tcp-synack.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_tcp_ack.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_tcp_psh.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_tcp_syn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_udpbypass.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_urg.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_xmas.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_xsyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_yummy.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc-unknown-linux-uclibc_Os_zsyn.json` | **sparc_uclibc_gcc** | sparc_uclibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_DDoS1.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_DDoS2.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_DDoS3.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_Fud-Bypass.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_Linux.Dataseg.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_Lizzard Stresser.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_Prometheus v4.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_TriGemini.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_bashdoor.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_bluenurse.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_bot.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_bot_13.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_client.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_client_1.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_client_16.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_client_LizzardSquad.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_client_lulz.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_client_reaper.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_client_selfrep.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_client_void.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_enemy.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_flux.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_godlyhttp.c_[qbot_client]_lulz.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_hide.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_hide-_19.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_hide_19.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_jimmy-sfe.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_juno.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_kaiten.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_oreo.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_randomware.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_ranzou-sfe.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_server_16.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O0_yummy.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_DDoS1.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_DDoS2.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_DDoS3.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_Fud-Bypass.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_Linux.Dataseg.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_Lizzard Stresser.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_Prometheus v4.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_TriGemini.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_bashdoor.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_bluenurse.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_bot.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_bot_13.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_client.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_client_1.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_client_16.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_client_LizzardSquad.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_client_lulz.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_client_reaper.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_client_selfrep.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_client_void.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_enemy.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_flux.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_godlyhttp.c_[qbot_client]_lulz.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_hide.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_hide-_19.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_hide_19.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_jimmy-sfe.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_juno.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_kaiten.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_oreo.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_ranzou-sfe.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_server_16.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O1_yummy.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_DDoS1.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_DDoS2.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_DDoS3.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_Fud-Bypass.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_Linux.Dataseg.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_Lizzard Stresser.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_Prometheus v4.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_TriGemini.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_bashdoor.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_bluenurse.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_bot.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_bot_13.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_client.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_client_1.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_client_16.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_client_LizzardSquad.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_client_lulz.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_client_reaper.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_client_selfrep.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_client_void.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_enemy.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_flux.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_godlyhttp.c_[qbot_client]_lulz.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_hide.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_hide-_19.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_hide_19.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_jimmy-sfe.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_juno.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_kaiten.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_ranzou-sfe.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_server_16.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O2_yummy.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_DDoS1.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_DDoS2.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_DDoS3.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_Fud-Bypass.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_Linux.Dataseg.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_Lizzard Stresser.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_Prometheus v4.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_TriGemini.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_bashdoor.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_bluenurse.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_bot.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_bot_13.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_client.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_client_1.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_client_16.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_client_LizzardSquad.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_client_lulz.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_client_reaper.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_client_selfrep.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_client_void.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_enemy.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_flux.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_godlyhttp.c_[qbot_client]_lulz.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_hide.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_hide-_19.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_hide_19.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_jimmy-sfe.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_juno.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_kaiten.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_oreo.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_ranzou-sfe.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_server_16.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_O3_yummy.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_DDoS1.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_DDoS2.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_DDoS3.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_Fud-Bypass.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_Linux.Dataseg.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_Lizzard Stresser.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_Prometheus v4.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_TriGemini.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_bashdoor.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_bluenurse.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_bot.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_bot_13.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_client.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_client_1.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_client_16.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_client_LizzardSquad.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_client_lulz.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_client_reaper.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_client_selfrep.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_client_void.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_enemy.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_flux.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_godlyhttp.c_[qbot_client]_lulz.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_hide.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_hide-_19.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_hide_19.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_jimmy-sfe.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_juno.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_kaiten.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_oreo.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_ranzou-sfe.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_server_16.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `sparc64-unknown-linux-gnu_Os_yummy.json` | **sparc_glibc_gcc** | sparc_glibc_gcc |    Correcto |
| `x86_64-w64-mingw32_O0_Branko.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O0_Hunatcha.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O0_Hunatchab.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O0_Infector_Win32.MiniPig.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O0_hide-_19.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O0_hide.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O0_hide_19.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O0_programa.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O0_server_16.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O1_Branko.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O1_Hunatcha.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O1_Hunatchab.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O1_Infector_Win32.MiniPig.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O1_hide-_19.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O1_hide.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O1_hide_19.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O1_programa.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O1_server_16.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O2_Branko.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O2_Hunatcha.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O2_Hunatchab.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O2_Infector_Win32.MiniPig.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O2_hide-_19.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O2_hide.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O2_hide_19.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O2_programa.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O2_server_16.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O3_Branko.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O3_Hunatcha.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O3_Hunatchab.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O3_Infector_Win32.MiniPig.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O3_hide-_19.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O3_hide.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O3_hide_19.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O3_programa.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_O3_server_16.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_Os_Branko.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_Os_Hunatcha.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_Os_Hunatchab.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_Os_Infector_Win32.MiniPig.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_Os_hide-_19.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_Os_hide.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_Os_hide_19.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_Os_programa.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |
| `x86_64-w64-mingw32_Os_server_16.exe.json` | **x86_mingw_gcc** | x86_mingw_gcc |    Correcto |

## Anexo: Salida Cruda de MANTILLA

```text
File: ./tmp/arm64-unknown-linux-gnu_O0_Fud-Bypass.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O0_Linux.Dataseg.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O0_Lizzard Stresser.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O0_Prometheus v4.json
15
Most common prediction: arm_glibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-gnu_O0_TriGemini.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O0_bashdoor.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O0_bluenurse.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O0_client_1.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O0_client_16.json
19
Most common prediction: arm_glibc_gcc (Count: 16)
File: ./tmp/arm64-unknown-linux-gnu_O0_client_LizzardSquad.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O0_client_lulz.json
18
Most common prediction: arm_glibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-gnu_O0_client_reaper.json
17
Most common prediction: arm_glibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-gnu_O0_client_selfrep.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O0_client_void.json
20
Most common prediction: arm_glibc_gcc (Count: 17)
File: ./tmp/arm64-unknown-linux-gnu_O0_godlyhttp.c_[qbot_client]_lulz.json
20
Most common prediction: arm_glibc_gcc (Count: 17)
File: ./tmp/arm64-unknown-linux-gnu_O0_hide-_19.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O0_hide_19.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O0_jimmy-sfe.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O0_randomware.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O0_server_16.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O1_Fud-Bypass.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O1_Linux.Dataseg.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O1_Lizzard Stresser.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O1_Prometheus v4.json
15
Most common prediction: arm_glibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-gnu_O1_TriGemini.json
25
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O1_bashdoor.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O1_bluenurse.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O1_client_1.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O1_client_16.json
17
Most common prediction: arm_glibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-gnu_O1_client_LizzardSquad.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O1_client_lulz.json
20
Most common prediction: arm_glibc_gcc (Count: 17)
File: ./tmp/arm64-unknown-linux-gnu_O1_client_reaper.json
18
Most common prediction: arm_glibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-gnu_O1_client_selfrep.json
21
Most common prediction: arm_glibc_gcc (Count: 18)
File: ./tmp/arm64-unknown-linux-gnu_O1_client_void.json
19
Most common prediction: arm_glibc_gcc (Count: 16)
File: ./tmp/arm64-unknown-linux-gnu_O1_godlyhttp.c_[qbot_client]_lulz.json
17
Most common prediction: arm_glibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-gnu_O1_hide-_19.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O1_hide_19.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O1_jimmy-sfe.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O1_ranzou-sfe.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O1_server_16.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O2_Fud-Bypass.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O2_Linux.Dataseg.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O2_Lizzard Stresser.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O2_Prometheus v4.json
17
Most common prediction: arm_glibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-gnu_O2_TriGemini.json
20
Most common prediction: arm_glibc_gcc (Count: 17)
File: ./tmp/arm64-unknown-linux-gnu_O2_bashdoor.json
18
Most common prediction: arm_glibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-gnu_O2_bluenurse.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O2_client_1.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O2_client_16.json
19
Most common prediction: arm_glibc_gcc (Count: 17)
File: ./tmp/arm64-unknown-linux-gnu_O2_client_LizzardSquad.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O2_client_lulz.json
19
Most common prediction: arm_glibc_gcc (Count: 16)
File: ./tmp/arm64-unknown-linux-gnu_O2_client_reaper.json
20
Most common prediction: arm_glibc_gcc (Count: 17)
File: ./tmp/arm64-unknown-linux-gnu_O2_client_selfrep.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O2_client_void.json
18
Most common prediction: arm_glibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-gnu_O2_godlyhttp.c_[qbot_client]_lulz.json
21
Most common prediction: arm_glibc_gcc (Count: 18)
File: ./tmp/arm64-unknown-linux-gnu_O2_hide-_19.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O2_hide_19.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O2_jimmy-sfe.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O2_ranzou-sfe.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O2_server_16.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O3_Fud-Bypass.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O3_Linux.Dataseg.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O3_Lizzard Stresser.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O3_Prometheus v4.json
17
Most common prediction: arm_glibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-gnu_O3_TriGemini.json
20
Most common prediction: arm_glibc_gcc (Count: 17)
File: ./tmp/arm64-unknown-linux-gnu_O3_bashdoor.json
18
Most common prediction: arm_glibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-gnu_O3_bluenurse.json
24
Most common prediction: arm_glibc_gcc (Count: 21)
File: ./tmp/arm64-unknown-linux-gnu_O3_client_1.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O3_client_16.json
21
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O3_client_LizzardSquad.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O3_client_lulz.json
16
Most common prediction: arm_glibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-gnu_O3_client_reaper.json
17
Most common prediction: arm_glibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-gnu_O3_client_selfrep.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O3_client_void.json
21
Most common prediction: arm_glibc_gcc (Count: 18)
File: ./tmp/arm64-unknown-linux-gnu_O3_godlyhttp.c_[qbot_client]_lulz.json
21
Most common prediction: arm_glibc_gcc (Count: 18)
File: ./tmp/arm64-unknown-linux-gnu_O3_hide-_19.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O3_hide_19.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_O3_jimmy-sfe.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O3_ranzou-sfe.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_O3_server_16.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_Os_Fud-Bypass.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_Os_Linux.Dataseg.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_Os_Lizzard Stresser.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_Os_Prometheus v4.json
15
Most common prediction: arm_glibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-gnu_Os_TriGemini.json
22
Most common prediction: arm_glibc_gcc (Count: 17)
File: ./tmp/arm64-unknown-linux-gnu_Os_bashdoor.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_Os_bluenurse.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_Os_client_1.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_Os_client_16.json
20
Most common prediction: arm_glibc_gcc (Count: 17)
File: ./tmp/arm64-unknown-linux-gnu_Os_client_LizzardSquad.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_Os_client_lulz.json
18
Most common prediction: arm_glibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-gnu_Os_client_reaper.json
19
Most common prediction: arm_glibc_gcc (Count: 16)
File: ./tmp/arm64-unknown-linux-gnu_Os_client_selfrep.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_Os_client_void.json
18
Most common prediction: arm_glibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-gnu_Os_godlyhttp.c_[qbot_client]_lulz.json
19
Most common prediction: arm_glibc_gcc (Count: 16)
File: ./tmp/arm64-unknown-linux-gnu_Os_hide-_19.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_Os_hide_19.json
22
Most common prediction: arm_glibc_gcc (Count: 19)
File: ./tmp/arm64-unknown-linux-gnu_Os_jimmy-sfe.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-gnu_Os_ranzou-sfe.json
18
Most common prediction: arm_glibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-gnu_Os_server_16.json
23
Most common prediction: arm_glibc_gcc (Count: 20)
File: ./tmp/arm64-unknown-linux-musl_O0_Linux.Dataseg.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O0_Massacre.json
19
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O0_SeCshell.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O0_TriGemini.json
22
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O0_bashdoor.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O0_client_lulz.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O0_cnc_13.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O0_hide-_19.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O0_hide_19.json
22
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O0_jimmy-sfe.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O0_kaiten.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O0_programa_15.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O0_programa_17.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O0_randomware.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O0_reaper_reaper.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O0_server.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O0_server_1.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O0_server_16.json
22
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O0_server_LizzardSquad.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O0_server_void.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O0_start_void.json
19
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O1_Linux.Dataseg.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O1_Massacre.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O1_SeCshell.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O1_TriGemini.json
24
Most common prediction: arm_musl_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-musl_O1_bashdoor.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O1_client_lulz.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O1_cnc_13.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O1_hide-_19.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O1_hide_19.json
22
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O1_jimmy-sfe.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O1_kaiten.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O1_programa_15.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O1_programa_17.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O1_randomware.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O1_ranzou-sfe.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O1_reaper_reaper.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O1_server.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O1_server_1.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O1_server_16.json
22
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O1_server_LizzardSquad.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O1_server_void.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O1_start_void.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O2_Linux.Dataseg.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O2_Massacre.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O2_SeCshell.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O2_TriGemini.json
19
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O2_bashdoor.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O2_client_lulz.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O2_cnc_13.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O2_hide-_19.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O2_hide_19.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O2_jimmy-sfe.json
23
Most common prediction: arm_musl_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-musl_O2_kaiten.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O2_programa_15.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O2_programa_17.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O2_randomware.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O2_ranzou-sfe.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O2_reaper_reaper.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O2_server.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O2_server_1.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O2_server_16.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O2_server_LizzardSquad.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O2_server_void.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O2_start_void.json
19
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O3_Linux.Dataseg.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O3_Massacre.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O3_SeCshell.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O3_TriGemini.json
19
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O3_bashdoor.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O3_client_lulz.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-musl_O3_cnc_13.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O3_hide-_19.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O3_hide_19.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O3_jimmy-sfe.json
23
Most common prediction: arm_musl_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-musl_O3_kaiten.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O3_programa_15.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O3_programa_17.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O3_randomware.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O3_ranzou-sfe.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O3_reaper_reaper.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O3_server.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O3_server_1.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O3_server_16.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_O3_server_LizzardSquad.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_O3_server_void.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_O3_start_void.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_Os_Linux.Dataseg.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_Os_Massacre.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_Os_SeCshell.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_Os_TriGemini.json
19
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_Os_bashdoor.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_Os_client_lulz.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_Os_cnc_13.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_Os_hide-_19.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_Os_hide_19.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_Os_jimmy-sfe.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_Os_kaiten.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_Os_programa_15.json
29
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_Os_programa_17.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_Os_randomware.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_Os_ranzou-sfe.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_Os_reaper_reaper.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-musl_Os_server.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_Os_server_1.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_Os_server_16.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_Os_server_LizzardSquad.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-musl_Os_server_void.json
19
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-musl_Os_start_void.json
19
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_O0_CFuck1.2.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O0_Chargen.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O0_DDoS1.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O0_DDoS2.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O0_DDoS3.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O0_DOMINATE.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O0_Fud-Bypass.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O0_Heartbeat.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O0_Improved SSYN.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_Linux.Dataseg.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_Lizzard Stresser.json
20
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O0_Massacre.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_Netbios.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O0_Prometheus v4.json
18
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O0_Quake.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O0_SSDP.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_STCP.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O0_SeCshell.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_TriGemini.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O0_bashdoor.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O0_bluenurse.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O0_bot_13.json
25
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O0_client.json
20
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O0_client_1.json
20
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O0_client_16.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O0_client_LizzardSquad.json
20
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O0_client_lulz.json
21
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_client_reaper.json
22
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O0_client_selfrep.json
24
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O0_client_void.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O0_cnc_13.json
22
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_enemy.json
12
Most common prediction: arm_uclibc_gcc (Count: 8)
File: ./tmp/arm64-unknown-linux-uclibc_O0_essyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O0_godlyhttp.c_[qbot_client]_lulz.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O0_hide.json
25
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O0_hide-_19.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_hide_19.json
25
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O0_jimmy-sfe.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_juno.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O0_kaiten.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O0_mDNS.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_oreo.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O0_oudp.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_programa_15.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O0_programa_17.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O0_randomware.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_reaper_reaper.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_server.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_server_1.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_server_16.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_server_LizzardSquad.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_server_selfrep.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O0_server_void.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O0_start_void.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O0_telnet.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O0_yummy.json
25
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_CFuck1.2.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Chargen.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_DDoS1.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_DDoS2.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_DDoS3.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_DOMINATE.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_EQUINOX.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_EvilESP1-1.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O1_EvilESPV3.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Fud-Bypass.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Heartbeat.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Improved SSYN.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_KILLALLv2.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Linux.Dataseg.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Lizzard Stresser.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Massacre.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Netbios.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_OVH-VIP.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Prometheus v4.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Quake.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_SSDP.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_SSYN2.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_STCP.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_SeCshell.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_Syn.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_TCP-GEN.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_TS3.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_TriGemini.json
27
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_UDP.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_UFWSIv4.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_bashdoor.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_bluenurse.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_bot_13.json
26
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_brrr.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_client.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_client_1.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_client_16.json
22
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_client_LizzardSquad.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_client_lulz.json
27
Most common prediction: arm_uclibc_gcc (Count: 16)
File: ./tmp/arm64-unknown-linux-uclibc_O1_client_reaper.json
23
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_client_selfrep.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_client_void.json
23
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_cnc_13.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_csyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_enemy.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_fivemovh.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_flux.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_game.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_godlyhttp.c_[qbot_client]_lulz.json
23
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_hide.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_hide-_19.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_hide_19.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_jimmy-sfe.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_kaiten.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_mDNS.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_nova.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_oackv1.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O1_oreo.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O1_oudp.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_programa_15.json
27
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_programa_17.json
25
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_randomware.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_ranzou-sfe.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_reaper_reaper.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_rssyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_server.json
25
Most common prediction: arm_musl_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_server_1.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_server_16.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_server_LizzardSquad.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_server_selfrep.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_server_void.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O1_start_void.json
23
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_stcp.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_sybexv3.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_syn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_synopts.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_tcp.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_tcp-synack.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_tcp_ack.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_tcp_psh.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_tcp_syn.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_tcpabuse.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_udpbypass.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O1_udprand.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O1_urg.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_werrraaa.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_xmas.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O1_xsyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_yummy.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O1_zsyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_50x.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_CFuck1.2.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Chargen.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_DDoS1.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_DDoS2.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_DDoS3.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_DOMINATE.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_EQUINOX.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_EvilESP1-1.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_EvilESPV3.json
26
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Fud-Bypass.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_GHP.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Heartbeat.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Improved SSYN.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O2_KILLALLv2.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Linux.Dataseg.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Lizzard Stresser.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Massacre.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Netbios.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_OVH-VIP.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Prometheus v4.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Quake.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_SSDP.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_STCP.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_SeCshell.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_Syn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_TCP-GEN.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_TS3.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_TS3-VOXILITY.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_TriGemini.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_UDP.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_UFWSIv4.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_ack.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_bashdoor.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_bluenurse.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_bot.json
25
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O2_bot_13.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_brrr.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_client.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_O2_client_1.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_O2_client_16.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O2_client_LizzardSquad.json
19
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_O2_client_lulz.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O2_client_reaper.json
21
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_client_selfrep.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_client_void.json
21
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_cnc.json
23
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_cnc_13.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_enemy.json
21
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O2_fin.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_fivemovh.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O2_flux.json
22
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_O2_frag.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_godlyhttp.c_[qbot_client]_lulz.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O2_hide.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_hide-_19.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_hide_19.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_issyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_jimmy-sfe.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_kaiten.json
25
Most common prediction: arm_musl_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_kgb.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O2_mDNS.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_mixamp.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_nova.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_oackv1.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_oreo.json
21
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_oudp.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_programa_15.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_programa_17.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_psh.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_randomware.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_ranzou-sfe.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_reaper_reaper.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O2_rst.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_server.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_server_1.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_server_16.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_server_LizzardSquad.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_server_selfrep.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O2_server_void.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_O2_start_void.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O2_sybexv3.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O2_syn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_synopts.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_tcp.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O2_tcp-synack.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_tcp_ack.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_tcp_psh.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_tcp_syn.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_tcpabuse.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O2_udpbypass.json
22
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_O2_urg.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_werrraaa.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_xmas.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O2_yummy.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_50x.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_CFuck1.2.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Chargen.json
24
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_DDoS1.json
21
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_DDoS2.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_DDoS3.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_DOMINATE.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_EQUINOX.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_EvilESP1-1.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_EvilESPV3.json
26
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Fud-Bypass.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_GHP.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Heartbeat.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Improved SSYN.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O3_KILLALLv2.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Linux.Dataseg.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Lizzard Stresser.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Massacre.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Netbios.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_OVH-VIP.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Prometheus v4.json
15
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Quake.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_SSDP.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_STCP.json
27
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_SeCshell.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_Syn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_TCP-GEN.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_TS3.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_TS3-VOXILITY.json
24
Most common prediction: arm_musl_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_TriGemini.json
24
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_UDP.json
24
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_UFWSIv4.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_amptfo.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_atcp.json
27
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_bashdoor.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_bluenurse.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_bot.json
25
Most common prediction: arm_musl_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_bot_13.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_client.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_client_1.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_client_16.json
25
Most common prediction: arm_musl_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_client_LizzardSquad.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_client_lulz.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_client_reaper.json
22
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_client_selfrep.json
22
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_client_void.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_cnc.json
21
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_cnc_13.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_enemy.json
15
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-uclibc_O3_fin.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_fivemovh.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_flux.json
22
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_godlyhttp.c_[qbot_client]_lulz.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O3_hide.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_hide-_19.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_hide_19.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_imperium.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_issyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O3_jimmy-sfe.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_kaiten.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_O3_kgb.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_mDNS.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_nova.json
23
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_oackv1.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_oreo.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_oudp.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_programa_15.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O3_programa_17.json
25
Most common prediction: arm_musl_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_psh.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_randomware.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_ranzou-sfe.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_rawudp.json
26
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_reaper_reaper.json
19
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_rst.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_server.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_server_1.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_server_16.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_server_LizzardSquad.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_server_selfrep.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_server_void.json
21
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_start_void.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_O3_sybexv3.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_O3_syn.json
27
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_synopts.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_O3_tcp.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_O3_tcp-synack.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_tcp_ack.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_tcp_psh.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_tcp_syn.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_udpbypass.json
22
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_O3_urg.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_xmas.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_O3_yummy.json
18
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_Os_50x.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_CFuck1.2.json
27
Most common prediction: arm_uclibc_gcc (Count: 16)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Chargen.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_DDoS1.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_DDoS2.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_DDoS3.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_DOMINATE.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_EQUINOX.json
26
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_EvilESP1-1.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_EvilESPV3.json
26
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Fud-Bypass.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_GHP.json
19
Most common prediction: arm_musl_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Heartbeat.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Improved SSYN.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_KILLALLv2.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Linux.Dataseg.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Lizzard Stresser.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Massacre.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Netbios.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_OVH-VIP.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Prometheus v4.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Quake.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_SSDP.json
23
Most common prediction: arm_musl_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_Os_STCP.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_SeCshell.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_Syn.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_TCP-GEN.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_TS3.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_TS3-VOXILITY.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_Os_TriGemini.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_Os_UDP.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_UFWSIv4.json
24
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_atcp.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_bashdoor.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_bluenurse.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_bogus.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_bot.json
22
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_bot_13.json
25
Most common prediction: arm_musl_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_brrr.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_client.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_client_1.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_client_16.json
16
Most common prediction: arm_uclibc_gcc (Count: 9)
File: ./tmp/arm64-unknown-linux-uclibc_Os_client_LizzardSquad.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_client_lulz.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_client_reaper.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_Os_client_selfrep.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_client_void.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_Os_cnc.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_Os_cnc_13.json
21
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_csyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_enemy.json
27
Most common prediction: arm_uclibc_gcc (Count: 16)
File: ./tmp/arm64-unknown-linux-uclibc_Os_fin.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_fivemovh.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_flux.json
22
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_Os_game.json
26
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_godlyhttp.c_[qbot_client]_lulz.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_Os_grev2.json
28
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_hide.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_hide-_19.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_hide_19.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_issyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_jimmy-sfe.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_juno.json
26
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_kaiten.json
25
Most common prediction: arm_musl_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_kgb.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_mDNS.json
25
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_mixamp.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_nova.json
23
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_oackv1.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_oreo.json
21
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_oudp.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_programa_15.json
33
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_programa_17.json
23
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_Os_psh.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_randomware.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_ranzou-sfe.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_reaper_reaper.json
21
Most common prediction: arm_uclibc_gcc (Count: 11)
File: ./tmp/arm64-unknown-linux-uclibc_Os_rssyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_rst.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_server.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_server_1.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_server_16.json
25
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_server_LizzardSquad.json
25
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_server_selfrep.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_Os_server_void.json
21
Most common prediction: arm_musl_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_Os_start_void.json
21
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_Os_stcp.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_sybexv3.json
24
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_syn.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_synopts.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_tcp.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_tcp-synack.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_tcp_ack.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_tcp_psh.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_tcp_syn.json
25
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_tcpabuse.json
27
Most common prediction: arm_uclibc_gcc (Count: 13)
File: ./tmp/arm64-unknown-linux-uclibc_Os_udpbypass.json
22
Most common prediction: arm_uclibc_gcc (Count: 10)
File: ./tmp/arm64-unknown-linux-uclibc_Os_urg.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_werrraaa.json
27
Most common prediction: arm_uclibc_gcc (Count: 14)
File: ./tmp/arm64-unknown-linux-uclibc_Os_xmas.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_xsyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/arm64-unknown-linux-uclibc_Os_yummy.json
23
Most common prediction: arm_uclibc_gcc (Count: 12)
File: ./tmp/arm64-unknown-linux-uclibc_Os_zsyn.json
27
Most common prediction: arm_uclibc_gcc (Count: 15)
File: ./tmp/mips-unknown-linux-gnu_O0_Linux.Dataseg.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O0_Lizzard Stresser.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O0_Prometheus v4.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O0_client_LizzardSquad.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O0_client_lulz.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O0_client_reaper.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O0_client_selfrep.json
14
Most common prediction: mips_glibc_gcc (Count: 11)
File: ./tmp/mips-unknown-linux-gnu_O0_client_void.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O0_godlyhttp.c_[qbot_client]_lulz.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O1_Linux.Dataseg.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O1_Lizzard Stresser.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O1_Prometheus v4.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O1_client_LizzardSquad.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O1_client_lulz.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O1_client_reaper.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O1_client_selfrep.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O1_client_void.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O1_godlyhttp.c_[qbot_client]_lulz.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O2_Linux.Dataseg.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O2_Lizzard Stresser.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O2_Prometheus v4.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O2_client_LizzardSquad.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O2_client_lulz.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O2_client_reaper.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O2_client_selfrep.json
13
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O2_client_void.json
14
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips-unknown-linux-gnu_O2_godlyhttp.c_[qbot_client]_lulz.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O3_Linux.Dataseg.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O3_Lizzard Stresser.json
14
Most common prediction: mips_glibc_gcc (Count: 11)
File: ./tmp/mips-unknown-linux-gnu_O3_Prometheus v4.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O3_client_LizzardSquad.json
14
Most common prediction: mips_glibc_gcc (Count: 11)
File: ./tmp/mips-unknown-linux-gnu_O3_client_lulz.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O3_client_reaper.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_O3_client_selfrep.json
14
Most common prediction: mips_glibc_gcc (Count: 11)
File: ./tmp/mips-unknown-linux-gnu_O3_client_void.json
14
Most common prediction: mips_glibc_gcc (Count: 11)
File: ./tmp/mips-unknown-linux-gnu_O3_godlyhttp.c_[qbot_client]_lulz.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_Os_Fud-Bypass.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_Os_Linux.Dataseg.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_Os_Lizzard Stresser.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_Os_Prometheus v4.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_Os_client_LizzardSquad.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_Os_client_lulz.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_Os_client_reaper.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_Os_client_selfrep.json
14
Most common prediction: mips_glibc_gcc (Count: 11)
File: ./tmp/mips-unknown-linux-gnu_Os_client_void.json
13
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_Os_godlyhttp.c_[qbot_client]_lulz.json
14
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-gnu_Os_ranzou-sfe.json
14
Most common prediction: mips_glibc_gcc (Count: 11)
File: ./tmp/mips-unknown-linux-musl_O0_Linux.Dataseg.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O0_TriGemini.json
5
Most common prediction: mips_musl_gcc (Count: 5)
File: ./tmp/mips-unknown-linux-musl_O0_client_lulz.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O0_jimmy-sfe.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O0_programa_15.json
13
Most common prediction: mips_musl_gcc (Count: 13)
File: ./tmp/mips-unknown-linux-musl_O0_programa_17.json
5
Most common prediction: mips_musl_gcc (Count: 5)
File: ./tmp/mips-unknown-linux-musl_O0_randomware.json
15
Most common prediction: mips_musl_gcc (Count: 15)
File: ./tmp/mips-unknown-linux-musl_O0_reaper_reaper.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O0_server_16.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O0_server_LizzardSquad.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O0_server_void.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O0_start_void.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O1_Linux.Dataseg.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O1_TriGemini.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O1_client_lulz.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O1_jimmy-sfe.json
5
Most common prediction: mips_musl_gcc (Count: 5)
File: ./tmp/mips-unknown-linux-musl_O1_programa_15.json
13
Most common prediction: mips_musl_gcc (Count: 13)
File: ./tmp/mips-unknown-linux-musl_O1_programa_17.json
5
Most common prediction: mips_musl_gcc (Count: 5)
File: ./tmp/mips-unknown-linux-musl_O1_randomware.json
15
Most common prediction: mips_musl_gcc (Count: 15)
File: ./tmp/mips-unknown-linux-musl_O1_ranzou-sfe.json
5
Most common prediction: mips_musl_gcc (Count: 5)
File: ./tmp/mips-unknown-linux-musl_O1_reaper_reaper.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O1_server_16.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O1_server_LizzardSquad.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O1_server_void.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O1_start_void.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O2_Linux.Dataseg.json
5
Most common prediction: mips_musl_gcc (Count: 5)
File: ./tmp/mips-unknown-linux-musl_O2_TriGemini.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O2_client_lulz.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O2_jimmy-sfe.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O2_programa_15.json
13
Most common prediction: mips_musl_gcc (Count: 13)
File: ./tmp/mips-unknown-linux-musl_O2_programa_17.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O2_randomware.json
15
Most common prediction: mips_musl_gcc (Count: 15)
File: ./tmp/mips-unknown-linux-musl_O2_ranzou-sfe.json
5
Most common prediction: mips_musl_gcc (Count: 5)
File: ./tmp/mips-unknown-linux-musl_O2_reaper_reaper.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O2_server_16.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O2_server_LizzardSquad.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O2_server_void.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O2_start_void.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O3_Linux.Dataseg.json
5
Most common prediction: mips_musl_gcc (Count: 5)
File: ./tmp/mips-unknown-linux-musl_O3_TriGemini.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O3_client_lulz.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O3_jimmy-sfe.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O3_programa_15.json
13
Most common prediction: mips_musl_gcc (Count: 13)
File: ./tmp/mips-unknown-linux-musl_O3_programa_17.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O3_randomware.json
15
Most common prediction: mips_musl_gcc (Count: 15)
File: ./tmp/mips-unknown-linux-musl_O3_ranzou-sfe.json
5
Most common prediction: mips_musl_gcc (Count: 5)
File: ./tmp/mips-unknown-linux-musl_O3_reaper_reaper.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O3_server_16.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O3_server_LizzardSquad.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O3_server_void.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_O3_start_void.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_Os_Linux.Dataseg.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_Os_TriGemini.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_Os_client_lulz.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_Os_jimmy-sfe.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_Os_programa_15.json
15
Most common prediction: mips_musl_gcc (Count: 13)
File: ./tmp/mips-unknown-linux-musl_Os_programa_17.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_Os_randomware.json
15
Most common prediction: mips_musl_gcc (Count: 15)
File: ./tmp/mips-unknown-linux-musl_Os_ranzou-sfe.json
5
Most common prediction: mips_musl_gcc (Count: 5)
File: ./tmp/mips-unknown-linux-musl_Os_reaper_reaper.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_Os_server_16.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_Os_server_LizzardSquad.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_Os_server_void.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips-unknown-linux-musl_Os_start_void.json
10
Most common prediction: mips_musl_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O0_Linux.Dataseg.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O0_Lizzard Stresser.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O0_Prometheus v4.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O0_client_LizzardSquad.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O0_client_reaper.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O0_client_selfrep.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O0_godlyhttp.c_[qbot_client]_lulz.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O1_Linux.Dataseg.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O1_Lizzard Stresser.json
16
Most common prediction: mips_glibc_gcc (Count: 11)
File: ./tmp/mips64-unknown-linux-gnu_O1_Prometheus v4.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O1_client_LizzardSquad.json
16
Most common prediction: mips_glibc_gcc (Count: 11)
File: ./tmp/mips64-unknown-linux-gnu_O1_client_reaper.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O1_client_selfrep.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O1_godlyhttp.c_[qbot_client]_lulz.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O2_Linux.Dataseg.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O2_Lizzard Stresser.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O2_Prometheus v4.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O2_client_LizzardSquad.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O2_client_reaper.json
16
Most common prediction: mips_glibc_gcc (Count: 8)
File: ./tmp/mips64-unknown-linux-gnu_O2_client_selfrep.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O2_godlyhttp.c_[qbot_client]_lulz.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O3_Linux.Dataseg.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O3_Lizzard Stresser.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O3_Prometheus v4.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O3_client_LizzardSquad.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_O3_client_reaper.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O3_client_selfrep.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_O3_godlyhttp.c_[qbot_client]_lulz.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_Os_Linux.Dataseg.json
16
Most common prediction: mips_glibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-gnu_Os_Lizzard Stresser.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_Os_Prometheus v4.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_Os_client_LizzardSquad.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_Os_client_reaper.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-gnu_Os_client_selfrep.json
16
Most common prediction: mips_glibc_gcc (Count: 11)
File: ./tmp/mips64-unknown-linux-gnu_Os_godlyhttp.c_[qbot_client]_lulz.json
16
Most common prediction: mips_glibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_CFuck1.2.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_Chargen.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_DOMINATE.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_Fud-Bypass.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_Heartbeat.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_Improved SSYN.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_KILLALLv2.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_Linux.Dataseg.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_Lizzard Stresser.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_Massacre.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_Netbios.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_Prometheus v4.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_SeCshell.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_TriGemini.json
10
Most common prediction: mips_uclibc_gcc (Count: 8)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_bashdoor.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_bluenurse.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_client_1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_client_16.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_client_LizzardSquad.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_client_lulz.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_client_reaper.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_client_selfrep.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_client_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_godlyhttp.c_[qbot_client]_lulz.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_hide-_19.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_hide_19.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_jimmy-sfe.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_programa_15.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_programa_17.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_randomware.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_reaper_reaper.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_server_1.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_server_16.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_server_LizzardSquad.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_server_selfrep.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_server_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_start_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O0_tcp_syn.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_CFuck1.2.json
10
Most common prediction: mips_uclibc_gcc (Count: 8)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_Chargen.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_DOMINATE.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_EQUINOX.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_EvilESP1-1.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_EvilESPV3.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_Fud-Bypass.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_Heartbeat.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_Improved SSYN.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_KILLALLv2.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_Linux.Dataseg.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_Lizzard Stresser.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_Massacre.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_Netbios.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_OVH-VIP.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_Prometheus v4.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_SeCshell.json
10
Most common prediction: mips_uclibc_gcc (Count: 8)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_TCP-GEN.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_TriGemini.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_UFWSIv4.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_bashdoor.json
10
Most common prediction: mips_uclibc_gcc (Count: 7)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_bluenurse.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_client_1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_client_16.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_client_LizzardSquad.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_client_lulz.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_client_reaper.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_client_selfrep.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_client_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_fivemovh.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_godlyhttp.c_[qbot_client]_lulz.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_hide-_19.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_hide_19.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_jimmy-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 8)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_programa_15.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_programa_17.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_randomware.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_ranzou-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 7)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_reaper_reaper.json
15
Most common prediction: mips_uclibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_server_1.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_server_16.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_server_LizzardSquad.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_server_selfrep.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_server_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_start_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_sybexv3.json
10
Most common prediction: mips_uclibc_gcc (Count: 8)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_synopts.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_tcp-synack.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_tcp_ack.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_tcp_psh.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_tcp_syn.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O1_udpbypass.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_CFuck1.2.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_Chargen.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_DOMINATE.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_EQUINOX.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_EvilESP1-1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_EvilESPV3.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_Fud-Bypass.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_Heartbeat.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_Improved SSYN.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_KILLALLv2.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_Linux.Dataseg.json
10
Most common prediction: mips_uclibc_gcc (Count: 8)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_Lizzard Stresser.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_Massacre.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_Netbios.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_OVH-VIP.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_Prometheus v4.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_SeCshell.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_TCP-GEN.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_TriGemini.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_UFWSIv4.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_bashdoor.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_bluenurse.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_client_1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_client_16.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_client_LizzardSquad.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_client_lulz.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_client_reaper.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_client_selfrep.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_client_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_fivemovh.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_godlyhttp.c_[qbot_client]_lulz.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_hide-_19.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_hide_19.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_jimmy-sfe.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_programa_15.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_programa_17.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_randomware.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_ranzou-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_reaper_reaper.json
15
Most common prediction: mips_uclibc_gcc (Count: 11)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_server_1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_server_16.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_server_LizzardSquad.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_server_selfrep.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_server_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_start_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_sybexv3.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_synopts.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_tcp-synack.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_tcp_ack.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_tcp_psh.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_tcp_syn.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O2_udpbypass.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_CFuck1.2.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_Chargen.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_DOMINATE.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_EQUINOX.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_EvilESP1-1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_EvilESPV3.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_Fud-Bypass.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_Heartbeat.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_Improved SSYN.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_KILLALLv2.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_Linux.Dataseg.json
10
Most common prediction: mips_uclibc_gcc (Count: 8)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_Lizzard Stresser.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_Massacre.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_Netbios.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_OVH-VIP.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_Prometheus v4.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_SeCshell.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_TCP-GEN.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_TriGemini.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_UFWSIv4.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_bashdoor.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_bluenurse.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_client_1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_client_16.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_client_LizzardSquad.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_client_lulz.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_client_reaper.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_client_selfrep.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_client_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_fivemovh.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_godlyhttp.c_[qbot_client]_lulz.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_hide-_19.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_hide_19.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_jimmy-sfe.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_programa_15.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_programa_17.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_randomware.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_ranzou-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 9)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_reaper_reaper.json
15
Most common prediction: mips_uclibc_gcc (Count: 11)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_server_1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_server_16.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_server_LizzardSquad.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_server_selfrep.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_server_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_start_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_sybexv3.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_synopts.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_tcp-synack.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_tcp_ack.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_tcp_psh.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_tcp_syn.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_O3_udpbypass.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_CFuck1.2.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_Chargen.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_DOMINATE.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_EQUINOX.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_EvilESP1-1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_EvilESPV3.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_Fud-Bypass.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_Heartbeat.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_Improved SSYN.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_KILLALLv2.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_Linux.Dataseg.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_Lizzard Stresser.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_Massacre.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_Netbios.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_OVH-VIP.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_Prometheus v4.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_SeCshell.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_TCP-GEN.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_TriGemini.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_UFWSIv4.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_bashdoor.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_bluenurse.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_client_1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_client_16.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_client_LizzardSquad.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_client_lulz.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_client_reaper.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_client_selfrep.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_client_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_fivemovh.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_godlyhttp.c_[qbot_client]_lulz.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_hide-_19.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_hide_19.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_jimmy-sfe.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_programa_15.json
17
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_programa_17.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_randomware.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_ranzou-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 7)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_reaper_reaper.json
15
Most common prediction: mips_uclibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_server_1.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_server_16.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_server_LizzardSquad.json
15
Most common prediction: mips_uclibc_gcc (Count: 12)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_server_selfrep.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_server_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_start_void.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_sybexv3.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_synopts.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_tcp-synack.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_tcp_ack.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_tcp_psh.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_tcp_syn.json
15
Most common prediction: mips_uclibc_gcc (Count: 13)
File: ./tmp/mips64-unknown-linux-uclibcn32_Os_udpbypass.json
15
Most common prediction: mips_uclibc_gcc (Count: 14)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_CFuck1.2.json
10
Most common prediction: mips_glibc_gcc (Count: 4)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_Chargen.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_DOMINATE.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_Fud-Bypass.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_Heartbeat.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_Improved SSYN.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_Linux.Dataseg.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_Lizzard Stresser.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_Netbios.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_Prometheus v4.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_SeCshell.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_TriGemini.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_bashdoor.json
10
Most common prediction: mips_uclibc_gcc (Count: 7)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_bluenurse.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_client_1.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_client_16.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_client_LizzardSquad.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_client_lulz.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_client_reaper.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_client_selfrep.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_client_void.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_godlyhttp.c_[qbot_client]_lulz.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_hide-_19.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_hide_19.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_jimmy-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_programa_15.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_programa_17.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_randomware.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_ranzou-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_reaper_reaper.json
10
Most common prediction: mips_uclibc_gcc (Count: 7)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_server_1.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_server_16.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_server_LizzardSquad.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_server_selfrep.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_server_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O0_start_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_CFuck1.2.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_Chargen.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_DOMINATE.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_Fud-Bypass.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_Heartbeat.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_Improved SSYN.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_Linux.Dataseg.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_Lizzard Stresser.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_Netbios.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_OVH-VIP.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_Prometheus v4.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_SeCshell.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_TriGemini.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_bashdoor.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_bluenurse.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_client_1.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_client_16.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_client_LizzardSquad.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_client_lulz.json
10
Most common prediction: mips_uclibc_gcc (Count: 4)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_client_reaper.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_client_selfrep.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_client_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_godlyhttp.c_[qbot_client]_lulz.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_hide-_19.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_hide_19.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_jimmy-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_programa_15.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_programa_17.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_randomware.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_ranzou-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_reaper_reaper.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_server_1.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_server_16.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_server_LizzardSquad.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_server_selfrep.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_server_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_start_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_sybexv3.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_tcp-synack.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_tcp_ack.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_tcp_psh.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_tcp_syn.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O1_udpbypass.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_CFuck1.2.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_Chargen.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_DOMINATE.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_Fud-Bypass.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_Heartbeat.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_Improved SSYN.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_Linux.Dataseg.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_Lizzard Stresser.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_Netbios.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_OVH-VIP.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_Prometheus v4.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_SeCshell.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_TriGemini.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_bashdoor.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_bluenurse.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_client_1.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_client_16.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_client_LizzardSquad.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_client_lulz.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_client_reaper.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_client_selfrep.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_client_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_godlyhttp.c_[qbot_client]_lulz.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_hide-_19.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_hide_19.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_jimmy-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_programa_15.json
15
Most common prediction: mips_uclibc_gcc (Count: 10)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_programa_17.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_randomware.json
10
Most common prediction: mips_uclibc_gcc (Count: 7)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_ranzou-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_reaper_reaper.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_server_1.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_server_16.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_server_LizzardSquad.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_server_selfrep.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_server_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_start_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_sybexv3.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_tcp-synack.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_tcp_ack.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_tcp_psh.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_tcp_syn.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O2_udpbypass.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_CFuck1.2.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_Chargen.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_DOMINATE.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_Fud-Bypass.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_Heartbeat.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_Improved SSYN.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_Linux.Dataseg.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_Lizzard Stresser.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_Massacre.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_Netbios.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_OVH-VIP.json
10
Most common prediction: mips_uclibc_gcc (Count: 7)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_Prometheus v4.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_SeCshell.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_TriGemini.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_bashdoor.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_bluenurse.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_bot_13.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_client.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_client_1.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_client_16.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_client_LizzardSquad.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_client_lulz.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_client_reaper.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_client_selfrep.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_client_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_cnc_13.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_godlyhttp.c_[qbot_client]_lulz.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_hide-_19.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_hide_19.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_jimmy-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_kaiten.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_oackv1.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_programa_15.json
15
Most common prediction: mips_uclibc_gcc (Count: 11)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_programa_17.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_randomware.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_ranzou-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_reaper_reaper.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_server.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_server_1.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_server_16.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_server_LizzardSquad.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_server_selfrep.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_server_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_start_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_sybexv3.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_tcp-synack.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_tcp_ack.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_tcp_psh.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_tcp_syn.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_O3_udpbypass.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_CFuck1.2.json
10
Most common prediction: mips_uclibc_gcc (Count: 7)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_Chargen.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_DOMINATE.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_Fud-Bypass.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_Heartbeat.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_Improved SSYN.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_Linux.Dataseg.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_Lizzard Stresser.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_Netbios.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_OVH-VIP.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_Prometheus v4.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_SeCshell.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_TriGemini.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_bashdoor.json
10
Most common prediction: mips_uclibc_gcc (Count: 7)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_bluenurse.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_bot_13.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_client.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_client_1.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_client_16.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_client_LizzardSquad.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_client_lulz.json
11
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_client_reaper.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_client_selfrep.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_client_void.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_cnc_13.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_godlyhttp.c_[qbot_client]_lulz.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_hide-_19.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_hide_19.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_jimmy-sfe.json
10
Most common prediction: mips_uclibc_gcc (Count: 7)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_kaiten.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_oackv1.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_programa_15.json
20
Most common prediction: mips_uclibc_gcc (Count: 15)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_programa_17.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_randomware.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_ranzou-sfe.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_reaper_reaper.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_server.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_server_1.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_server_16.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_server_LizzardSquad.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_server_selfrep.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_server_void.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_start_void.json
10
Most common prediction: mips_glibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_sybexv3.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_tcp-synack.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_tcp_ack.json
10
Most common prediction: mips_uclibc_gcc (Count: 5)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_tcp_psh.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_tcp_syn.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/mips64-unknown-linux-uclibcn64_Os_udpbypass.json
10
Most common prediction: mips_uclibc_gcc (Count: 6)
File: ./tmp/ppc-unknown-linux-gnu_O0_DDoS1.json
215
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O0_DDoS2.json
113
Most common prediction: ppc_glibc_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-gnu_O0_DDoS3.json
122
Most common prediction: ppc_glibc_gcc (Count: 67)
File: ./tmp/ppc-unknown-linux-gnu_O0_Fud-Bypass.json
90
Most common prediction: ppc_glibc_gcc (Count: 34)
File: ./tmp/ppc-unknown-linux-gnu_O0_Linux.Dataseg.json
54
Most common prediction: ppc_glibc_gcc (Count: 33)
File: ./tmp/ppc-unknown-linux-gnu_O0_Lizzard Stresser.json
129
Most common prediction: ppc_glibc_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-gnu_O0_Prometheus v4.json
123
Most common prediction: ppc_glibc_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-gnu_O0_TriGemini.json
57
Most common prediction: ppc_glibc_gcc (Count: 33)
File: ./tmp/ppc-unknown-linux-gnu_O0_bashdoor.json
48
Most common prediction: ppc_glibc_gcc (Count: 25)
File: ./tmp/ppc-unknown-linux-gnu_O0_bluenurse.json
60
Most common prediction: ppc_glibc_gcc (Count: 36)
File: ./tmp/ppc-unknown-linux-gnu_O0_bot.json
199
Most common prediction: ppc_glibc_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-gnu_O0_bot_13.json
120
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O0_client.json
129
Most common prediction: ppc_glibc_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-gnu_O0_client_1.json
129
Most common prediction: ppc_glibc_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-gnu_O0_client_16.json
246
Most common prediction: ppc_glibc_gcc (Count: 74)
File: ./tmp/ppc-unknown-linux-gnu_O0_client_LizzardSquad.json
129
Most common prediction: ppc_glibc_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-gnu_O0_client_lulz.json
163
Most common prediction: ppc_glibc_gcc (Count: 86)
File: ./tmp/ppc-unknown-linux-gnu_O0_client_reaper.json
147
Most common prediction: ppc_glibc_gcc (Count: 78)
File: ./tmp/ppc-unknown-linux-gnu_O0_client_selfrep.json
122
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O0_client_void.json
136
Most common prediction: ppc_glibc_gcc (Count: 73)
File: ./tmp/ppc-unknown-linux-gnu_O0_enemy.json
171
Most common prediction: ppc_glibc_gcc (Count: 91)
File: ./tmp/ppc-unknown-linux-gnu_O0_flux.json
57
Most common prediction: ppc_glibc_gcc (Count: 32)
File: ./tmp/ppc-unknown-linux-gnu_O0_godlyhttp.c_[qbot_client]_lulz.json
147
Most common prediction: ppc_glibc_gcc (Count: 78)
File: ./tmp/ppc-unknown-linux-gnu_O0_hide.json
32
Most common prediction: ppc_glibc_gcc (Count: 21)
File: ./tmp/ppc-unknown-linux-gnu_O0_hide-_19.json
44
Most common prediction: ppc_glibc_gcc (Count: 22)
File: ./tmp/ppc-unknown-linux-gnu_O0_hide_19.json
32
Most common prediction: ppc_glibc_gcc (Count: 21)
File: ./tmp/ppc-unknown-linux-gnu_O0_jimmy-sfe.json
49
Most common prediction: ppc_glibc_gcc (Count: 30)
File: ./tmp/ppc-unknown-linux-gnu_O0_kaiten.json
215
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O0_oreo.json
130
Most common prediction: ppc_glibc_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-gnu_O0_randomware.json
60
Most common prediction: ppc_glibc_gcc (Count: 35)
File: ./tmp/ppc-unknown-linux-gnu_O0_server_16.json
34
Most common prediction: ppc_glibc_gcc (Count: 22)
File: ./tmp/ppc-unknown-linux-gnu_O0_yummy.json
123
Most common prediction: ppc_glibc_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-gnu_O1_DDoS1.json
116
Most common prediction: ppc_glibc_gcc (Count: 64)
File: ./tmp/ppc-unknown-linux-gnu_O1_DDoS2.json
116
Most common prediction: ppc_glibc_gcc (Count: 64)
File: ./tmp/ppc-unknown-linux-gnu_O1_DDoS3.json
122
Most common prediction: ppc_glibc_gcc (Count: 67)
File: ./tmp/ppc-unknown-linux-gnu_O1_Fud-Bypass.json
62
Most common prediction: ppc_glibc_gcc (Count: 37)
File: ./tmp/ppc-unknown-linux-gnu_O1_Linux.Dataseg.json
54
Most common prediction: ppc_glibc_gcc (Count: 33)
File: ./tmp/ppc-unknown-linux-gnu_O1_Lizzard Stresser.json
219
Most common prediction: ppc_glibc_gcc (Count: 67)
File: ./tmp/ppc-unknown-linux-gnu_O1_Prometheus v4.json
155
Most common prediction: ppc_glibc_gcc (Count: 81)
File: ./tmp/ppc-unknown-linux-gnu_O1_TriGemini.json
52
Most common prediction: ppc_glibc_gcc (Count: 30)
File: ./tmp/ppc-unknown-linux-gnu_O1_bashdoor.json
48
Most common prediction: ppc_glibc_gcc (Count: 25)
File: ./tmp/ppc-unknown-linux-gnu_O1_bluenurse.json
58
Most common prediction: ppc_glibc_gcc (Count: 34)
File: ./tmp/ppc-unknown-linux-gnu_O1_bot.json
108
Most common prediction: ppc_glibc_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-gnu_O1_bot_13.json
216
Most common prediction: ppc_glibc_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-gnu_O1_client.json
219
Most common prediction: ppc_glibc_gcc (Count: 67)
File: ./tmp/ppc-unknown-linux-gnu_O1_client_1.json
220
Most common prediction: ppc_glibc_gcc (Count: 68)
File: ./tmp/ppc-unknown-linux-gnu_O1_client_16.json
234
Most common prediction: ppc_glibc_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-gnu_O1_client_LizzardSquad.json
219
Most common prediction: ppc_glibc_gcc (Count: 67)
File: ./tmp/ppc-unknown-linux-gnu_O1_client_lulz.json
158
Most common prediction: ppc_glibc_gcc (Count: 83)
File: ./tmp/ppc-unknown-linux-gnu_O1_client_reaper.json
148
Most common prediction: ppc_glibc_gcc (Count: 77)
File: ./tmp/ppc-unknown-linux-gnu_O1_client_selfrep.json
122
Most common prediction: ppc_glibc_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-gnu_O1_client_void.json
132
Most common prediction: ppc_glibc_gcc (Count: 71)
File: ./tmp/ppc-unknown-linux-gnu_O1_enemy.json
288
Most common prediction: ppc_glibc_gcc (Count: 87)
File: ./tmp/ppc-unknown-linux-gnu_O1_flux.json
53
Most common prediction: ppc_glibc_gcc (Count: 31)
File: ./tmp/ppc-unknown-linux-gnu_O1_godlyhttp.c_[qbot_client]_lulz.json
153
Most common prediction: ppc_glibc_gcc (Count: 81)
File: ./tmp/ppc-unknown-linux-gnu_O1_hide.json
30
Most common prediction: ppc_glibc_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-gnu_O1_hide-_19.json
46
Most common prediction: ppc_glibc_gcc (Count: 24)
File: ./tmp/ppc-unknown-linux-gnu_O1_hide_19.json
30
Most common prediction: ppc_glibc_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-gnu_O1_jimmy-sfe.json
51
Most common prediction: ppc_glibc_gcc (Count: 29)
File: ./tmp/ppc-unknown-linux-gnu_O1_kaiten.json
116
Most common prediction: ppc_glibc_gcc (Count: 64)
File: ./tmp/ppc-unknown-linux-gnu_O1_oreo.json
243
Most common prediction: ppc_glibc_gcc (Count: 73)
File: ./tmp/ppc-unknown-linux-gnu_O1_ranzou-sfe.json
94
Most common prediction: ppc_glibc_gcc (Count: 37)
File: ./tmp/ppc-unknown-linux-gnu_O1_server_16.json
32
Most common prediction: ppc_glibc_gcc (Count: 21)
File: ./tmp/ppc-unknown-linux-gnu_O1_yummy.json
238
Most common prediction: ppc_glibc_gcc (Count: 72)
File: ./tmp/ppc-unknown-linux-gnu_O2_DDoS1.json
129
Most common prediction: ppc_glibc_gcc (Count: 71)
File: ./tmp/ppc-unknown-linux-gnu_O2_DDoS2.json
113
Most common prediction: ppc_glibc_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-gnu_O2_DDoS3.json
127
Most common prediction: ppc_glibc_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-gnu_O2_Fud-Bypass.json
62
Most common prediction: ppc_glibc_gcc (Count: 37)
File: ./tmp/ppc-unknown-linux-gnu_O2_Linux(1).Dataseg.json
52
Most common prediction: ppc_glibc_gcc (Count: 31)
File: ./tmp/ppc-unknown-linux-gnu_O2_Linux.Dataseg.json
52
Most common prediction: ppc_glibc_gcc (Count: 31)
File: ./tmp/ppc-unknown-linux-gnu_O2_Lizzard Stresser.json
124
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O2_Prometheus v4.json
151
Most common prediction: ppc_glibc_gcc (Count: 78)
File: ./tmp/ppc-unknown-linux-gnu_O2_TriGemini.json
54
Most common prediction: ppc_glibc_gcc (Count: 33)
File: ./tmp/ppc-unknown-linux-gnu_O2_bashdoor.json
48
Most common prediction: ppc_glibc_gcc (Count: 25)
File: ./tmp/ppc-unknown-linux-gnu_O2_bluenurse.json
65
Most common prediction: ppc_glibc_gcc (Count: 39)
File: ./tmp/ppc-unknown-linux-gnu_O2_bot.json
110
Most common prediction: ppc_glibc_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-gnu_O2_bot_13.json
114
Most common prediction: ppc_glibc_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-gnu_O2_client.json
124
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O2_client_1.json
122
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O2_client_16.json
135
Most common prediction: ppc_glibc_gcc (Count: 71)
File: ./tmp/ppc-unknown-linux-gnu_O2_client_LizzardSquad.json
124
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O2_client_lulz.json
161
Most common prediction: ppc_glibc_gcc (Count: 84)
File: ./tmp/ppc-unknown-linux-gnu_O2_client_reaper.json
153
Most common prediction: ppc_glibc_gcc (Count: 81)
File: ./tmp/ppc-unknown-linux-gnu_O2_client_selfrep.json
122
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O2_client_void.json
141
Most common prediction: ppc_glibc_gcc (Count: 76)
File: ./tmp/ppc-unknown-linux-gnu_O2_enemy.json
165
Most common prediction: ppc_glibc_gcc (Count: 86)
File: ./tmp/ppc-unknown-linux-gnu_O2_flux.json
53
Most common prediction: ppc_glibc_gcc (Count: 31)
File: ./tmp/ppc-unknown-linux-gnu_O2_godlyhttp.c_[qbot_client]_lulz.json
156
Most common prediction: ppc_glibc_gcc (Count: 84)
File: ./tmp/ppc-unknown-linux-gnu_O2_hide.json
30
Most common prediction: ppc_glibc_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-gnu_O2_hide-_19.json
44
Most common prediction: ppc_glibc_gcc (Count: 22)
File: ./tmp/ppc-unknown-linux-gnu_O2_hide_19.json
30
Most common prediction: ppc_glibc_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-gnu_O2_jimmy-sfe.json
51
Most common prediction: ppc_glibc_gcc (Count: 29)
File: ./tmp/ppc-unknown-linux-gnu_O2_kaiten.json
129
Most common prediction: ppc_glibc_gcc (Count: 71)
File: ./tmp/ppc-unknown-linux-gnu_O2_oreo.json
136
Most common prediction: ppc_glibc_gcc (Count: 73)
File: ./tmp/ppc-unknown-linux-gnu_O2_ranzou-sfe.json
92
Most common prediction: ppc_glibc_gcc (Count: 35)
File: ./tmp/ppc-unknown-linux-gnu_O2_server_16.json
32
Most common prediction: ppc_glibc_gcc (Count: 21)
File: ./tmp/ppc-unknown-linux-gnu_O2_yummy.json
242
Most common prediction: ppc_glibc_gcc (Count: 74)
File: ./tmp/ppc-unknown-linux-gnu_O3_DDoS1.json
231
Most common prediction: ppc_glibc_gcc (Count: 69)
File: ./tmp/ppc-unknown-linux-gnu_O3_DDoS2.json
111
Most common prediction: ppc_glibc_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-gnu_O3_DDoS3.json
124
Most common prediction: ppc_glibc_gcc (Count: 68)
File: ./tmp/ppc-unknown-linux-gnu_O3_Fud-Bypass.json
62
Most common prediction: ppc_glibc_gcc (Count: 37)
File: ./tmp/ppc-unknown-linux-gnu_O3_Linux.Dataseg.json
52
Most common prediction: ppc_glibc_gcc (Count: 31)
File: ./tmp/ppc-unknown-linux-gnu_O3_Lizzard Stresser.json
124
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O3_Prometheus v4.json
134
Most common prediction: ppc_glibc_gcc (Count: 69)
File: ./tmp/ppc-unknown-linux-gnu_O3_TriGemini.json
76
Most common prediction: ppc_glibc_gcc (Count: 32)
File: ./tmp/ppc-unknown-linux-gnu_O3_bashdoor.json
48
Most common prediction: ppc_glibc_gcc (Count: 25)
File: ./tmp/ppc-unknown-linux-gnu_O3_bluenurse.json
60
Most common prediction: ppc_glibc_gcc (Count: 36)
File: ./tmp/ppc-unknown-linux-gnu_O3_bot.json
201
Most common prediction: ppc_glibc_gcc (Count: 63)
File: ./tmp/ppc-unknown-linux-gnu_O3_bot_13.json
116
Most common prediction: ppc_glibc_gcc (Count: 64)
File: ./tmp/ppc-unknown-linux-gnu_O3_client.json
122
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O3_client_1.json
122
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O3_client_16.json
136
Most common prediction: ppc_glibc_gcc (Count: 72)
File: ./tmp/ppc-unknown-linux-gnu_O3_client_LizzardSquad.json
124
Most common prediction: ppc_glibc_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-gnu_O3_client_lulz.json
177
Most common prediction: ppc_glibc_gcc (Count: 94)
File: ./tmp/ppc-unknown-linux-gnu_O3_client_reaper.json
150
Most common prediction: ppc_glibc_gcc (Count: 79)
File: ./tmp/ppc-unknown-linux-gnu_O3_client_selfrep.json
122
Most common prediction: ppc_glibc_gcc (Count: 64)
File: ./tmp/ppc-unknown-linux-gnu_O3_client_void.json
138
Most common prediction: ppc_glibc_gcc (Count: 72)
File: ./tmp/ppc-unknown-linux-gnu_O3_enemy.json
170
Most common prediction: ppc_glibc_gcc (Count: 88)
File: ./tmp/ppc-unknown-linux-gnu_O3_flux.json
57
Most common prediction: ppc_glibc_gcc (Count: 33)
File: ./tmp/ppc-unknown-linux-gnu_O3_godlyhttp.c_[qbot_client]_lulz.json
149
Most common prediction: ppc_glibc_gcc (Count: 79)
File: ./tmp/ppc-unknown-linux-gnu_O3_hide.json
30
Most common prediction: ppc_glibc_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-gnu_O3_hide-_19.json
44
Most common prediction: ppc_glibc_gcc (Count: 22)
File: ./tmp/ppc-unknown-linux-gnu_O3_hide_19.json
30
Most common prediction: ppc_glibc_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-gnu_O3_jimmy-sfe.json
51
Most common prediction: ppc_glibc_gcc (Count: 30)
File: ./tmp/ppc-unknown-linux-gnu_O3_kaiten.json
231
Most common prediction: ppc_glibc_gcc (Count: 69)
File: ./tmp/ppc-unknown-linux-gnu_O3_oreo.json
138
Most common prediction: ppc_glibc_gcc (Count: 75)
File: ./tmp/ppc-unknown-linux-gnu_O3_ranzou-sfe.json
92
Most common prediction: ppc_glibc_gcc (Count: 35)
File: ./tmp/ppc-unknown-linux-gnu_O3_server_16.json
28
Most common prediction: ppc_glibc_gcc (Count: 18)
File: ./tmp/ppc-unknown-linux-gnu_O3_yummy.json
133
Most common prediction: ppc_glibc_gcc (Count: 71)
File: ./tmp/ppc-unknown-linux-gnu_Os_DDoS1.json
131
Most common prediction: ppc_glibc_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-gnu_Os_DDoS2.json
120
Most common prediction: ppc_glibc_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-gnu_Os_DDoS3.json
131
Most common prediction: ppc_glibc_gcc (Count: 72)
File: ./tmp/ppc-unknown-linux-gnu_Os_Fud-Bypass.json
60
Most common prediction: ppc_glibc_gcc (Count: 35)
File: ./tmp/ppc-unknown-linux-gnu_Os_Linux.Dataseg.json
76
Most common prediction: ppc_glibc_gcc (Count: 31)
File: ./tmp/ppc-unknown-linux-gnu_Os_Lizzard Stresser.json
120
Most common prediction: ppc_glibc_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-gnu_Os_Prometheus v4.json
157
Most common prediction: ppc_glibc_gcc (Count: 83)
File: ./tmp/ppc-unknown-linux-gnu_Os_TriGemini.json
76
Most common prediction: ppc_glibc_gcc (Count: 32)
File: ./tmp/ppc-unknown-linux-gnu_Os_bashdoor.json
46
Most common prediction: ppc_glibc_gcc (Count: 23)
File: ./tmp/ppc-unknown-linux-gnu_Os_bluenurse.json
60
Most common prediction: ppc_glibc_gcc (Count: 36)
File: ./tmp/ppc-unknown-linux-gnu_Os_bot.json
104
Most common prediction: ppc_glibc_gcc (Count: 57)
File: ./tmp/ppc-unknown-linux-gnu_Os_bot_13.json
206
Most common prediction: ppc_glibc_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-gnu_Os_client.json
120
Most common prediction: ppc_glibc_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-gnu_Os_client_1.json
120
Most common prediction: ppc_glibc_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-gnu_Os_client_16.json
234
Most common prediction: ppc_glibc_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-gnu_Os_client_LizzardSquad.json
120
Most common prediction: ppc_glibc_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-gnu_Os_client_lulz.json
162
Most common prediction: ppc_glibc_gcc (Count: 85)
File: ./tmp/ppc-unknown-linux-gnu_Os_client_reaper.json
145
Most common prediction: ppc_glibc_gcc (Count: 76)
File: ./tmp/ppc-unknown-linux-gnu_Os_client_selfrep.json
233
Most common prediction: ppc_glibc_gcc (Count: 71)
File: ./tmp/ppc-unknown-linux-gnu_Os_client_void.json
241
Most common prediction: ppc_glibc_gcc (Count: 71)
File: ./tmp/ppc-unknown-linux-gnu_Os_enemy.json
163
Most common prediction: ppc_glibc_gcc (Count: 86)
File: ./tmp/ppc-unknown-linux-gnu_Os_flux.json
56
Most common prediction: ppc_glibc_gcc (Count: 33)
File: ./tmp/ppc-unknown-linux-gnu_Os_godlyhttp.c_[qbot_client]_lulz.json
152
Most common prediction: ppc_glibc_gcc (Count: 81)
File: ./tmp/ppc-unknown-linux-gnu_Os_hide.json
30
Most common prediction: ppc_glibc_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-gnu_Os_hide-_19.json
36
Most common prediction: ppc_glibc_gcc (Count: 24)
File: ./tmp/ppc-unknown-linux-gnu_Os_hide_19.json
30
Most common prediction: ppc_glibc_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-gnu_Os_jimmy-sfe.json
51
Most common prediction: ppc_glibc_gcc (Count: 30)
File: ./tmp/ppc-unknown-linux-gnu_Os_kaiten.json
131
Most common prediction: ppc_glibc_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-gnu_Os_oreo.json
128
Most common prediction: ppc_glibc_gcc (Count: 69)
File: ./tmp/ppc-unknown-linux-gnu_Os_ranzou-sfe.json
90
Most common prediction: ppc_glibc_gcc (Count: 34)
File: ./tmp/ppc-unknown-linux-gnu_Os_server_16.json
34
Most common prediction: ppc_glibc_gcc (Count: 22)
File: ./tmp/ppc-unknown-linux-gnu_Os_yummy.json
238
Most common prediction: ppc_glibc_gcc (Count: 72)
File: ./tmp/ppc-unknown-linux-musl_O0_DDoS1.json
115
Most common prediction: ppc_musl_gcc (Count: 56)
File: ./tmp/ppc-unknown-linux-musl_O0_DDoS3.json
129
Most common prediction: ppc_musl_gcc (Count: 63)
File: ./tmp/ppc-unknown-linux-musl_O0_Linux.Dataseg.json
73
Most common prediction: ppc_musl_gcc (Count: 28)
File: ./tmp/ppc-unknown-linux-musl_O0_Massacre.json
55
Most common prediction: ppc_musl_gcc (Count: 26)
File: ./tmp/ppc-unknown-linux-musl_O0_SeCshell.json
39
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_O0_TriGemini.json
62
Most common prediction: ppc_musl_gcc (Count: 30)
File: ./tmp/ppc-unknown-linux-musl_O0_bashdoor.json
55
Most common prediction: ppc_musl_gcc (Count: 24)
File: ./tmp/ppc-unknown-linux-musl_O0_bot.json
117
Most common prediction: ppc_musl_gcc (Count: 56)
File: ./tmp/ppc-unknown-linux-musl_O0_c7.json
142
Most common prediction: ppc_musl_gcc (Count: 68)
File: ./tmp/ppc-unknown-linux-musl_O0_client_lulz.json
288
Most common prediction: ppc_musl_gcc (Count: 82)
File: ./tmp/ppc-unknown-linux-musl_O0_cnc.json
122
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_O0_cnc_13.json
122
Most common prediction: ppc_musl_gcc (Count: 59)
File: ./tmp/ppc-unknown-linux-musl_O0_enemy.json
174
Most common prediction: ppc_musl_gcc (Count: 84)
File: ./tmp/ppc-unknown-linux-musl_O0_hide.json
41
Most common prediction: ppc_musl_gcc (Count: 19)
File: ./tmp/ppc-unknown-linux-musl_O0_hide-_19.json
41
Most common prediction: ppc_musl_gcc (Count: 19)
File: ./tmp/ppc-unknown-linux-musl_O0_hide_19.json
41
Most common prediction: ppc_musl_gcc (Count: 19)
File: ./tmp/ppc-unknown-linux-musl_O0_jimmy-sfe.json
63
Most common prediction: ppc_musl_gcc (Count: 29)
File: ./tmp/ppc-unknown-linux-musl_O0_kaiten.json
115
Most common prediction: ppc_musl_gcc (Count: 56)
File: ./tmp/ppc-unknown-linux-musl_O0_programa_15.json
135
Most common prediction: ppc_musl_gcc (Count: 67)
File: ./tmp/ppc-unknown-linux-musl_O0_programa_17.json
122
Most common prediction: ppc_musl_gcc (Count: 58)
File: ./tmp/ppc-unknown-linux-musl_O0_randomware.json
66
Most common prediction: ppc_musl_gcc (Count: 34)
File: ./tmp/ppc-unknown-linux-musl_O0_reaper_reaper.json
122
Most common prediction: ppc_musl_gcc (Count: 59)
File: ./tmp/ppc-unknown-linux-musl_O0_server.json
181
Most common prediction: ppc_musl_gcc (Count: 54)
File: ./tmp/ppc-unknown-linux-musl_O0_server_1.json
181
Most common prediction: ppc_musl_gcc (Count: 54)
File: ./tmp/ppc-unknown-linux-musl_O0_server_16.json
41
Most common prediction: ppc_musl_gcc (Count: 18)
File: ./tmp/ppc-unknown-linux-musl_O0_server_LizzardSquad.json
181
Most common prediction: ppc_musl_gcc (Count: 54)
File: ./tmp/ppc-unknown-linux-musl_O0_server_void.json
122
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-musl_O0_start_void.json
122
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_O1_DDoS1.json
119
Most common prediction: ppc_musl_gcc (Count: 58)
File: ./tmp/ppc-unknown-linux-musl_O1_DDoS3.json
224
Most common prediction: ppc_musl_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-musl_O1_Linux.Dataseg.json
55
Most common prediction: ppc_musl_gcc (Count: 27)
File: ./tmp/ppc-unknown-linux-musl_O1_Massacre.json
55
Most common prediction: ppc_musl_gcc (Count: 24)
File: ./tmp/ppc-unknown-linux-musl_O1_SeCshell.json
39
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_O1_TriGemini.json
87
Most common prediction: ppc_musl_gcc (Count: 33)
File: ./tmp/ppc-unknown-linux-musl_O1_bashdoor.json
47
Most common prediction: ppc_musl_gcc (Count: 22)
File: ./tmp/ppc-unknown-linux-musl_O1_bot.json
124
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-musl_O1_c7.json
138
Most common prediction: ppc_musl_gcc (Count: 66)
File: ./tmp/ppc-unknown-linux-musl_O1_client_lulz.json
165
Most common prediction: ppc_musl_gcc (Count: 80)
File: ./tmp/ppc-unknown-linux-musl_O1_cnc.json
124
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_O1_cnc_13.json
215
Most common prediction: ppc_musl_gcc (Count: 64)
File: ./tmp/ppc-unknown-linux-musl_O1_enemy.json
174
Most common prediction: ppc_musl_gcc (Count: 84)
File: ./tmp/ppc-unknown-linux-musl_O1_hide.json
41
Most common prediction: ppc_musl_gcc (Count: 19)
File: ./tmp/ppc-unknown-linux-musl_O1_hide-_19.json
41
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_O1_hide_19.json
41
Most common prediction: ppc_musl_gcc (Count: 19)
File: ./tmp/ppc-unknown-linux-musl_O1_jimmy-sfe.json
63
Most common prediction: ppc_musl_gcc (Count: 29)
File: ./tmp/ppc-unknown-linux-musl_O1_kaiten.json
119
Most common prediction: ppc_musl_gcc (Count: 58)
File: ./tmp/ppc-unknown-linux-musl_O1_programa_15.json
128
Most common prediction: ppc_musl_gcc (Count: 64)
File: ./tmp/ppc-unknown-linux-musl_O1_programa_17.json
120
Most common prediction: ppc_musl_gcc (Count: 59)
File: ./tmp/ppc-unknown-linux-musl_O1_randomware.json
69
Most common prediction: ppc_musl_gcc (Count: 34)
File: ./tmp/ppc-unknown-linux-musl_O1_ranzou-sfe.json
68
Most common prediction: ppc_musl_gcc (Count: 34)
File: ./tmp/ppc-unknown-linux-musl_O1_reaper_reaper.json
124
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_O1_server.json
181
Most common prediction: ppc_musl_gcc (Count: 55)
File: ./tmp/ppc-unknown-linux-musl_O1_server_1.json
110
Most common prediction: ppc_musl_gcc (Count: 54)
File: ./tmp/ppc-unknown-linux-musl_O1_server_16.json
41
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_O1_server_LizzardSquad.json
181
Most common prediction: ppc_musl_gcc (Count: 55)
File: ./tmp/ppc-unknown-linux-musl_O1_server_void.json
128
Most common prediction: ppc_musl_gcc (Count: 63)
File: ./tmp/ppc-unknown-linux-musl_O1_start_void.json
124
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_O2_DDoS1.json
128
Most common prediction: ppc_musl_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-musl_O2_DDoS3.json
123
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-musl_O2_Linux.Dataseg.json
71
Most common prediction: ppc_musl_gcc (Count: 28)
File: ./tmp/ppc-unknown-linux-musl_O2_Massacre.json
55
Most common prediction: ppc_musl_gcc (Count: 26)
File: ./tmp/ppc-unknown-linux-musl_O2_SeCshell.json
37
Most common prediction: ppc_musl_gcc (Count: 18)
File: ./tmp/ppc-unknown-linux-musl_O2_TriGemini.json
60
Most common prediction: ppc_musl_gcc (Count: 31)
File: ./tmp/ppc-unknown-linux-musl_O2_bashdoor.json
45
Most common prediction: ppc_musl_gcc (Count: 23)
File: ./tmp/ppc-unknown-linux-musl_O2_bot.json
208
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_O2_c7.json
253
Most common prediction: ppc_musl_gcc (Count: 71)
File: ./tmp/ppc-unknown-linux-musl_O2_client_lulz.json
170
Most common prediction: ppc_musl_gcc (Count: 84)
File: ./tmp/ppc-unknown-linux-musl_O2_cnc.json
126
Most common prediction: ppc_musl_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-musl_O2_cnc_13.json
126
Most common prediction: ppc_musl_gcc (Count: 63)
File: ./tmp/ppc-unknown-linux-musl_O2_enemy.json
174
Most common prediction: ppc_musl_gcc (Count: 84)
File: ./tmp/ppc-unknown-linux-musl_O2_hide.json
41
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_O2_hide-_19.json
39
Most common prediction: ppc_musl_gcc (Count: 18)
File: ./tmp/ppc-unknown-linux-musl_O2_hide_19.json
41
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_O2_jimmy-sfe.json
58
Most common prediction: ppc_musl_gcc (Count: 27)
File: ./tmp/ppc-unknown-linux-musl_O2_kaiten.json
131
Most common prediction: ppc_musl_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-musl_O2_programa_15.json
126
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-musl_O2_programa_17.json
117
Most common prediction: ppc_musl_gcc (Count: 55)
File: ./tmp/ppc-unknown-linux-musl_O2_randomware.json
63
Most common prediction: ppc_musl_gcc (Count: 30)
File: ./tmp/ppc-unknown-linux-musl_O2_ranzou-sfe.json
67
Most common prediction: ppc_musl_gcc (Count: 32)
File: ./tmp/ppc-unknown-linux-musl_O2_reaper_reaper.json
120
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_O2_server.json
108
Most common prediction: ppc_musl_gcc (Count: 52)
File: ./tmp/ppc-unknown-linux-musl_O2_server_1.json
112
Most common prediction: ppc_musl_gcc (Count: 54)
File: ./tmp/ppc-unknown-linux-musl_O2_server_16.json
41
Most common prediction: ppc_musl_gcc (Count: 19)
File: ./tmp/ppc-unknown-linux-musl_O2_server_LizzardSquad.json
108
Most common prediction: ppc_musl_gcc (Count: 51)
File: ./tmp/ppc-unknown-linux-musl_O2_server_void.json
122
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-musl_O2_start_void.json
120
Most common prediction: ppc_musl_gcc (Count: 59)
File: ./tmp/ppc-unknown-linux-musl_O3_DDoS1.json
126
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_O3_DDoS3.json
123
Most common prediction: ppc_musl_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-musl_O3_Linux.Dataseg.json
71
Most common prediction: ppc_musl_gcc (Count: 28)
File: ./tmp/ppc-unknown-linux-musl_O3_Massacre.json
55
Most common prediction: ppc_musl_gcc (Count: 26)
File: ./tmp/ppc-unknown-linux-musl_O3_SeCshell.json
37
Most common prediction: ppc_musl_gcc (Count: 18)
File: ./tmp/ppc-unknown-linux-musl_O3_TriGemini.json
85
Most common prediction: ppc_musl_gcc (Count: 32)
File: ./tmp/ppc-unknown-linux-musl_O3_bashdoor.json
45
Most common prediction: ppc_musl_gcc (Count: 23)
File: ./tmp/ppc-unknown-linux-musl_O3_bot.json
210
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-musl_O3_c7.json
143
Most common prediction: ppc_musl_gcc (Count: 69)
File: ./tmp/ppc-unknown-linux-musl_O3_client_lulz.json
180
Most common prediction: ppc_musl_gcc (Count: 88)
File: ./tmp/ppc-unknown-linux-musl_O3_cnc.json
124
Most common prediction: ppc_musl_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-musl_O3_cnc_13.json
122
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_O3_enemy.json
176
Most common prediction: ppc_musl_gcc (Count: 85)
File: ./tmp/ppc-unknown-linux-musl_O3_hide.json
41
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_O3_hide-_19.json
39
Most common prediction: ppc_musl_gcc (Count: 18)
File: ./tmp/ppc-unknown-linux-musl_O3_hide_19.json
41
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_O3_jimmy-sfe.json
63
Most common prediction: ppc_musl_gcc (Count: 31)
File: ./tmp/ppc-unknown-linux-musl_O3_kaiten.json
126
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_O3_programa_15.json
126
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-musl_O3_programa_17.json
201
Most common prediction: ppc_musl_gcc (Count: 58)
File: ./tmp/ppc-unknown-linux-musl_O3_randomware.json
87
Most common prediction: ppc_musl_gcc (Count: 32)
File: ./tmp/ppc-unknown-linux-musl_O3_ranzou-sfe.json
67
Most common prediction: ppc_musl_gcc (Count: 32)
File: ./tmp/ppc-unknown-linux-musl_O3_reaper_reaper.json
211
Most common prediction: ppc_musl_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-musl_O3_server.json
106
Most common prediction: ppc_musl_gcc (Count: 50)
File: ./tmp/ppc-unknown-linux-musl_O3_server_1.json
197
Most common prediction: ppc_musl_gcc (Count: 58)
File: ./tmp/ppc-unknown-linux-musl_O3_server_16.json
39
Most common prediction: ppc_musl_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-musl_O3_server_LizzardSquad.json
106
Most common prediction: ppc_musl_gcc (Count: 50)
File: ./tmp/ppc-unknown-linux-musl_O3_server_void.json
120
Most common prediction: ppc_musl_gcc (Count: 59)
File: ./tmp/ppc-unknown-linux-musl_O3_start_void.json
122
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_Os_DDoS1.json
123
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-musl_Os_DDoS3.json
126
Most common prediction: ppc_musl_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-musl_Os_GHP.json
176
Most common prediction: ppc_musl_gcc (Count: 52)
File: ./tmp/ppc-unknown-linux-musl_Os_Linux.Dataseg.json
71
Most common prediction: ppc_musl_gcc (Count: 27)
File: ./tmp/ppc-unknown-linux-musl_Os_Massacre.json
53
Most common prediction: ppc_musl_gcc (Count: 27)
File: ./tmp/ppc-unknown-linux-musl_Os_SeCshell.json
37
Most common prediction: ppc_musl_gcc (Count: 19)
File: ./tmp/ppc-unknown-linux-musl_Os_TriGemini.json
62
Most common prediction: ppc_musl_gcc (Count: 30)
File: ./tmp/ppc-unknown-linux-musl_Os_bashdoor.json
55
Most common prediction: ppc_musl_gcc (Count: 24)
File: ./tmp/ppc-unknown-linux-musl_Os_bot.json
117
Most common prediction: ppc_musl_gcc (Count: 57)
File: ./tmp/ppc-unknown-linux-musl_Os_c7.json
134
Most common prediction: ppc_musl_gcc (Count: 65)
File: ./tmp/ppc-unknown-linux-musl_Os_client_lulz.json
163
Most common prediction: ppc_musl_gcc (Count: 80)
File: ./tmp/ppc-unknown-linux-musl_Os_cnc.json
120
Most common prediction: ppc_musl_gcc (Count: 59)
File: ./tmp/ppc-unknown-linux-musl_Os_cnc_13.json
122
Most common prediction: ppc_musl_gcc (Count: 59)
File: ./tmp/ppc-unknown-linux-musl_Os_enemy.json
171
Most common prediction: ppc_musl_gcc (Count: 84)
File: ./tmp/ppc-unknown-linux-musl_Os_flux.json
85
Most common prediction: ppc_musl_gcc (Count: 30)
File: ./tmp/ppc-unknown-linux-musl_Os_hide.json
41
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_Os_hide-_19.json
41
Most common prediction: ppc_musl_gcc (Count: 19)
File: ./tmp/ppc-unknown-linux-musl_Os_hide_19.json
41
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_Os_jimmy-sfe.json
63
Most common prediction: ppc_musl_gcc (Count: 29)
File: ./tmp/ppc-unknown-linux-musl_Os_kaiten.json
125
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-musl_Os_programa_15.json
141
Most common prediction: ppc_musl_gcc (Count: 70)
File: ./tmp/ppc-unknown-linux-musl_Os_programa_17.json
218
Most common prediction: ppc_musl_gcc (Count: 63)
File: ./tmp/ppc-unknown-linux-musl_Os_randomware.json
103
Most common prediction: ppc_musl_gcc (Count: 36)
File: ./tmp/ppc-unknown-linux-musl_Os_ranzou-sfe.json
68
Most common prediction: ppc_musl_gcc (Count: 33)
File: ./tmp/ppc-unknown-linux-musl_Os_reaper_reaper.json
120
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_Os_rudy.json
115
Most common prediction: ppc_musl_gcc (Count: 57)
File: ./tmp/ppc-unknown-linux-musl_Os_server.json
102
Most common prediction: ppc_musl_gcc (Count: 51)
File: ./tmp/ppc-unknown-linux-musl_Os_server_1.json
102
Most common prediction: ppc_musl_gcc (Count: 51)
File: ./tmp/ppc-unknown-linux-musl_Os_server_16.json
39
Most common prediction: ppc_musl_gcc (Count: 20)
File: ./tmp/ppc-unknown-linux-musl_Os_server_LizzardSquad.json
102
Most common prediction: ppc_musl_gcc (Count: 51)
File: ./tmp/ppc-unknown-linux-musl_Os_server_void.json
122
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-musl_Os_slow.json
113
Most common prediction: ppc_musl_gcc (Count: 56)
File: ./tmp/ppc-unknown-linux-musl_Os_start_void.json
120
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-uclibc_O0_50x.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_CFuck1.2.json
32
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Chargen.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_DDoS1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_DDoS2.json
128
Most common prediction: ppc_musl_gcc (Count: 61)
File: ./tmp/ppc-unknown-linux-uclibc_O0_DDoS3.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_DOMINATE.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Fud-Bypass.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Heartbeat.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Improved SSYN.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Linux.Dataseg.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Lizzard Stresser.json
27
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Massacre.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Netbios.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Prometheus v4.json
21
Most common prediction: ppc_uclibc_gcc (Count: 12)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Quake.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O0_SSDP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O0_STCP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_SeCshell.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_Syn.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_TS3.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O0_TriGemini.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_UDP.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_UDP_Telnet.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O0_UFWSIv4.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_bashdoor.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_bluenurse.json
23
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_bot.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_bot_13.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_c7.json
31
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_client.json
27
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_client_1.json
29
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_client_16.json
24
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_client_LizzardSquad.json
27
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_client_lulz.json
25
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_client_reaper.json
25
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_client_selfrep.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_client_void.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_cnc.json
126
Most common prediction: ppc_musl_gcc (Count: 58)
File: ./tmp/ppc-unknown-linux-uclibc_O0_cnc_13.json
130
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-uclibc_O0_enemy.json
26
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_godlyhttp.c_[qbot_client]_lulz.json
25
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_grev2.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_hide.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O0_hide-_19.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_hide_19.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O0_imperium.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_jimmy-sfe.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_kaiten.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_mDNS.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O0_oreo.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_programa_15.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_programa_17.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_randomware.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_reaper_reaper.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_server.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_server_1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_server_16.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_server_LizzardSquad.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_server_selfrep.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_server_void.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O0_start_void.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O0_tcp.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O0_yummy.json
25
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_50x.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_CFuck1.2.json
32
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Chargen.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_DDoS1.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_DDoS2.json
122
Most common prediction: ppc_musl_gcc (Count: 57)
File: ./tmp/ppc-unknown-linux-uclibc_O1_DDoS3.json
26
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_DOMINATE.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_EQUINOX.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_EvilESP1-1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_EvilESPV3.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Fud-Bypass.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Heartbeat.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Improved SSYN.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_KILLALLv2.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Linux.Dataseg.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Lizzard Stresser.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Massacre.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Netbios.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_OVH-VIP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Prometheus v4.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Quake.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_SSDP.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_STCP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_SeCshell.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_Syn.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_TCP-GEN.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_TS3.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_TS3-VOXILITY.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_TriGemini.json
32
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_UDP.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_UDP_VSE.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_UFWSIv4.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_ZAP.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_atcp.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_bashdoor.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_bluenurse.json
23
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_bogus.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_bot.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_bot_13.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_brrr.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_c7.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_client.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_client_1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O1_client_16.json
25
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_client_LizzardSquad.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O1_client_lulz.json
23
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_client_reaper.json
25
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_client_selfrep.json
32
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O1_client_void.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O1_cnc.json
130
Most common prediction: ppc_musl_gcc (Count: 62)
File: ./tmp/ppc-unknown-linux-uclibc_O1_cnc_13.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_csyn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_enemy.json
20
Most common prediction: ppc_uclibc_gcc (Count: 11)
File: ./tmp/ppc-unknown-linux-uclibc_O1_essyn.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_fin.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_fivemovh.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_flux.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_game.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_godlyhttp.c_[qbot_client]_lulz.json
27
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_grev2.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_hide.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_hide-_19.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_hide_19.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_issyn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_jimmy-sfe.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_kaiten.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_kgb.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_mDNS.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_mixamp.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_nova.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_oackv1.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_oreo.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_oudp.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_programa_15.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_programa_17.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_psh.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_randomware.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O1_ranzou-sfe.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_reaper_reaper.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_rst.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_se.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_server.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_server_1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_server_16.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_server_LizzardSquad.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_server_selfrep.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_server_void.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_start_void.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_stcp.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_sybexv3.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_syn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_synfin.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_synopts.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_tcp.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_tcp-synack.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_tcp_ack.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_tcp_psh.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_tcp_syn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_tcpabuse.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_udpbypass.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_urg.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_werrraaa.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O1_wizard.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_xmas.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O1_xsyn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O1_yummy.json
27
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O1_zsyn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_50x.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_CFuck1.2.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Chargen.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_DDoS1.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_DDoS2.json
118
Most common prediction: ppc_musl_gcc (Count: 54)
File: ./tmp/ppc-unknown-linux-uclibc_O2_DDoS3.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_DOMINATE.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_EQUINOX.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_EvilESP1-1.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O2_EvilESPV3.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Fud-Bypass.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Heartbeat.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Improved SSYN.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_KILLALLv2.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Linux.Dataseg.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Lizzard Stresser.json
34
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Massacre.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Netbios.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_OVH-VIP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Prometheus v4.json
31
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Quake.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_SSDP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_STCP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_SeCshell.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_Syn.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_TCP-GEN.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_TS3.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_TS3-VOXILITY.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_TriGemini.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_UDP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_UFWSIv4.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_bashdoor.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_bluenurse.json
25
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_bot.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_bot_13.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_brrr.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_c7.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_client.json
34
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O2_client_1.json
31
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_client_16.json
26
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_client_LizzardSquad.json
34
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O2_client_lulz.json
25
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_client_reaper.json
27
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_client_selfrep.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_client_void.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O2_cnc.json
126
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-uclibc_O2_cnc_13.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_enemy.json
24
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_fin.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_fivemovh.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O2_flux.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_godlyhttp.c_[qbot_client]_lulz.json
25
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_hide.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_hide-_19.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_hide_19.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_issyn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_jimmy-sfe.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_kaiten.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_kgb.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_mDNS.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_mixamp.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O2_nova.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_oackv1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_oreo.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_oudp.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_programa_15.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_programa_17.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_psh.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_randomware.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_ranzou-sfe.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_reaper_reaper.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_rst.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_server.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_server_1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_server_16.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_server_LizzardSquad.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_server_selfrep.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_server_void.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_start_void.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_sybexv3.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_syn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_synopts.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O2_tcp.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_tcp-synack.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_tcp_ack.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_tcp_psh.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_tcp_syn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_tcpabuse.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O2_udpbypass.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O2_urg.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_werrraaa.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_xmas.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O2_xsyn.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O2_yummy.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O3_50x.json
28
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O3_CFuck1.2.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Chargen.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_DDoS1.json
31
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_DDoS2.json
122
Most common prediction: ppc_musl_gcc (Count: 58)
File: ./tmp/ppc-unknown-linux-uclibc_O3_DDoS3.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_DOMINATE.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_EQUINOX.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_EvilESP1-1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_EvilESPV3.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Fud-Bypass.json
30
Most common prediction: ppc_musl_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Heartbeat.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Improved SSYN.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_KILLALLv2.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Linux.Dataseg.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Lizzard Stresser.json
33
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Massacre.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Netbios.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_OVH-VIP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Prometheus v4.json
24
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Quake.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_SSDP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_SSYN2.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_STCP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O3_SeCshell.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_Syn.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_TCP-GEN.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_TS3.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_TS3-VOXILITY.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_TriGemini.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_UDP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_UFWSIv4.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_ack.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_amptfo.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O3_bashdoor.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_bluenurse.json
25
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_bot.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_bot_13.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_brrr.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_c7.json
31
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_client.json
34
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O3_client_1.json
33
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O3_client_16.json
26
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_client_LizzardSquad.json
33
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_O3_client_lulz.json
27
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_client_reaper.json
20
Most common prediction: ppc_uclibc_gcc (Count: 11)
File: ./tmp/ppc-unknown-linux-uclibc_O3_client_selfrep.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_client_void.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_cnc.json
128
Most common prediction: ppc_musl_gcc (Count: 63)
File: ./tmp/ppc-unknown-linux-uclibc_O3_cnc_13.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_enemy.json
25
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O3_essyn.json
30
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O3_fin.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_fivemovh.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_flux.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_godlyhttp.c_[qbot_client]_lulz.json
23
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_hide.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_hide-_19.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_hide_19.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_issyn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_jimmy-sfe.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_kaiten.json
31
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_kgb.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_mDNS.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_nova.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_oackv1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_oreo.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_oudp.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_programa_15.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_O3_programa_17.json
32
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_psh.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_randomware.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_ranzou-sfe.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_rawudp.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_reaper_reaper.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_rst.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_server.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_server_1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_server_16.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_server_LizzardSquad.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_server_selfrep.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_server_void.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_start_void.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_sybexv3.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_syn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_O3_synopts.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_tcp.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_tcp-synack.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_tcp_ack.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_tcp_psh.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_tcp_syn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_tcpabuse.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_udpbypass.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_O3_udprand.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_urg.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_werrraaa.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_xmas.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_O3_yummy.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_Os_50x.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_CFuck1.2.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Chargen.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_DDoS1.json
31
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_DDoS2.json
199
Most common prediction: ppc_musl_gcc (Count: 57)
File: ./tmp/ppc-unknown-linux-uclibc_Os_DDoS3.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_DOMINATE.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_EQUINOX.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_EvilESP1-1.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_EvilESPV3.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Fud-Bypass.json
28
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_Os_GHP.json
23
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Heartbeat.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Improved SSYN.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_KILLALLv2.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Linux.Dataseg.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Lizzard Stresser.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Massacre.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Netbios.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_OVH-VIP.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Prometheus v4.json
26
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Quake.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_SSDP.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_STCP.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_SeCshell.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_Syn.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_TCP-GEN.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_TS3.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_TS3-VOXILITY.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_TriGemini.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_UDP.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_UDP_Telnet.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_UFWSIv4.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_atcp.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_bashdoor.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_bluenurse.json
25
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_bogus.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_bot.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_bot_13.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_brrr.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_c7.json
26
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_Os_client.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_client_1.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_client_16.json
23
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_client_LizzardSquad.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_client_lulz.json
25
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_client_reaper.json
25
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_Os_client_selfrep.json
31
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_Os_client_void.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_Os_cnc.json
124
Most common prediction: ppc_musl_gcc (Count: 60)
File: ./tmp/ppc-unknown-linux-uclibc_Os_cnc_13.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_csyn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_enemy.json
27
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_fin.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_fivemovh.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_flux.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_game.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_godlyhttp.c_[qbot_client]_lulz.json
25
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_grev2.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_hide.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_hide-_19.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_hide_19.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_issyn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_jimmy-sfe.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_kaiten.json
31
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_kgb.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_mDNS.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_mixamp.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_nova.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_oackv1.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_oreo.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_oudp.json
28
Most common prediction: ppc_musl_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_Os_programa_15.json
36
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_programa_17.json
32
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_psh.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_randomware.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_ranzou-sfe.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_reaper_reaper.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_rst.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_rudy.json
23
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_Os_server.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_server_1.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_server_16.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_server_LizzardSquad.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_server_selfrep.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_server_void.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_slow.json
23
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_start_void.json
28
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_stcp.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_sybexv3.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_syn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_synopts.json
32
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_tcp.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_tcp-synack.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_tcp_ack.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_tcp_psh.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_tcp_syn.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_tcpabuse.json
30
Most common prediction: ppc_uclibc_gcc (Count: 13)
File: ./tmp/ppc-unknown-linux-uclibc_Os_telnet.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_udpbypass.json
30
Most common prediction: ppc_uclibc_gcc (Count: 16)
File: ./tmp/ppc-unknown-linux-uclibc_Os_urg.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_vse.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_werrraaa.json
30
Most common prediction: ppc_uclibc_gcc (Count: 14)
File: ./tmp/ppc-unknown-linux-uclibc_Os_xmas.json
30
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_xsyn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/ppc-unknown-linux-uclibc_Os_yummy.json
30
Most common prediction: ppc_uclibc_gcc (Count: 17)
File: ./tmp/ppc-unknown-linux-uclibc_Os_zsyn.json
28
Most common prediction: ppc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O0_CFuck1.2.json
23
Most common prediction: sparc_uclibc_gcc (Count: 22)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Chargen.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_DDoS1.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O0_DDoS2.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O0_DDoS3.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O0_DOMINATE.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O0_EQUINOX.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_EvilESPV3.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Fud-Bypass.json
17
Most common prediction: sparc_uclibc_gcc (Count: 17)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Heartbeat.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Improved SSYN.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Linux.Dataseg.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Lizzard Stresser.json
19
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Massacre.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Netbios.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Prometheus v4.json
19
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Quake.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_SSDP.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_STCP.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_SeCshell.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_Syn.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O0_TS3.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_TriGemini.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O0_UDP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_atcp.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O0_bashdoor.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_bluenurse.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O0_bot.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_bot_13.json
18
Most common prediction: sparc_uclibc_gcc (Count: 17)
File: ./tmp/sparc-unknown-linux-uclibc_O0_c7.json
7
Most common prediction: sparc_uclibc_gcc (Count: 7)
File: ./tmp/sparc-unknown-linux-uclibc_O0_client.json
19
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_client_1.json
19
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_client_16.json
21
Most common prediction: sparc_uclibc_gcc (Count: 18)
File: ./tmp/sparc-unknown-linux-uclibc_O0_client_LizzardSquad.json
19
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_client_lulz.json
19
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_client_reaper.json
18
Most common prediction: sparc_uclibc_gcc (Count: 18)
File: ./tmp/sparc-unknown-linux-uclibc_O0_client_selfrep.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O0_client_void.json
21
Most common prediction: sparc_uclibc_gcc (Count: 18)
File: ./tmp/sparc-unknown-linux-uclibc_O0_cnc.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O0_cnc_13.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_enemy.json
18
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O0_godlyhttp.c_[qbot_client]_lulz.json
19
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_hide.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_hide-_19.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_hide_19.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_jimmy-sfe.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O0_kaiten.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O0_mDNS.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_oreo.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_10.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_11.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_12.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_17.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_2.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_3.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_4.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_5.json
17
Most common prediction: sparc_uclibc_gcc (Count: 17)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_7.json
17
Most common prediction: sparc_uclibc_gcc (Count: 17)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_8.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_9.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O0_programa_9_1.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O0_randomware.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O0_reaper_reaper.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O0_rudy.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O0_server.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_server_1.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O0_server_16.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O0_server_LizzardSquad.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_server_selfrep.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_server_void.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_start_void.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O0_tcp.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O0_tcp-synack.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O0_yummy.json
19
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O1_50x.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_CFuck1.2.json
20
Most common prediction: sparc_uclibc_gcc (Count: 19)
File: ./tmp/sparc-unknown-linux-uclibc_O1_Chargen.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_DDoS1.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O1_DDoS2.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O1_DDoS3.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O1_DOMINATE.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_EQUINOX.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_EvilESP1-1.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_EvilESPV3.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O1_Fud-Bypass.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O1_GHP.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O1_Improved SSYN.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_KILLALLv2.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_Linux.Dataseg.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_Lizzard Stresser.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_Massacre.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O1_Netbios.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_OVH-VIP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_Prometheus v4.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_Quake.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_SSDP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_STCP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_SeCshell.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_Syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_TCP-GEN.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O1_TS3.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_TriGemini.json
12
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_UDP.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O1_UFWSIv4.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_atcp.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_bashdoor.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_bluenurse.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O1_bot.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_bot_13.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O1_c7.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_client.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_client_1.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_client_16.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_client_LizzardSquad.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_client_lulz.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O1_client_reaper.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_client_selfrep.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_client_void.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_cnc.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_cnc_13.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_csyn.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O1_enemy.json
19
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_fin.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_fivemovh.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O1_flux.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O1_game.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_godlyhttp.c_[qbot_client]_lulz.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_hide.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_hide-_19.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_hide_19.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_jimmy-sfe.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_kaiten.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O1_kgb.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O1_mDNS.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_nova.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O1_oackv1.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O1_oreo.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_oudp.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_10.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_11.json
16
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_12.json
18
Most common prediction: sparc_uclibc_gcc (Count: 17)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_17.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_2.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_3.json
14
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_4.json
14
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_5.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_7.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_8.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_9.json
18
Most common prediction: sparc_uclibc_gcc (Count: 17)
File: ./tmp/sparc-unknown-linux-uclibc_O1_programa_9_1.json
17
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O1_psh.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_randomware.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O1_ranzou-sfe.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_reaper_reaper.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_rst.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_rudy.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O1_server.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_server_1.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_server_16.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_server_LizzardSquad.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O1_server_selfrep.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_server_void.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_slow.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O1_start_void.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O1_stcp.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_sybexv3.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_syn.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O1_synopts.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O1_tcp.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_tcp-synack.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_tcp_ack.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_tcp_psh.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_tcp_syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_udpbypass.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O1_urg.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_xmas.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O1_xsyn.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O1_yummy.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O1_zsyn.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O2_50x.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O2_CFuck1.2.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Chargen.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_DDoS1.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O2_DDoS2.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O2_DDoS3.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O2_DOMINATE.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O2_EQUINOX.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_EvilESP1-1.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_EvilESPV3.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Fud-Bypass.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O2_GHP.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Heartbeat.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Improved SSYN.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_KILLALLv2.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Linux.Dataseg.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Lizzard Stresser.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Massacre.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Netbios.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_OVH-VIP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Prometheus v4.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Quake.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_SSDP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_STCP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_SeCshell.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_Syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_TCP-GEN.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_TS3.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_TriGemini.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_UDP.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O2_UFWSIv4.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_bashdoor.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_bluenurse.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O2_bot.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_bot_13.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O2_c7.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O2_client.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_client_1.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_client_16.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_client_LizzardSquad.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_client_lulz.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O2_client_reaper.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_client_selfrep.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_client_void.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_cnc.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_cnc_13.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O2_csyn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_enemy.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O2_fin.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_fivemovh.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O2_flux.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O2_game.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_godlyhttp.c_[qbot_client]_lulz.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_hide.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_hide-_19.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_hide_19.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_issyn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_jimmy-sfe.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O2_kaiten.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O2_kgb.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O2_mDNS.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_nova.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O2_oackv1.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_oreo.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_oudp.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_10.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_11.json
16
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_12.json
17
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_17.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_2.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_3.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_4.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_5.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_7.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_8.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_9.json
18
Most common prediction: sparc_uclibc_gcc (Count: 17)
File: ./tmp/sparc-unknown-linux-uclibc_O2_programa_9_1.json
17
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O2_psh.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_randomware.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O2_ranzou-sfe.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O2_reaper_reaper.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_rst.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_rudy.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O2_server.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O2_server_1.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O2_server_16.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O2_server_LizzardSquad.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O2_server_selfrep.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_server_void.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_slow.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O2_start_void.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_stcp.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_sybexv3.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_synopts.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O2_tcp.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_tcp-synack.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_tcp_ack.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_tcp_psh.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_tcp_syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_udpbypass.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_urg.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_xmas.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_xsyn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O2_yummy.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O2_zsyn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_50x.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O3_CFuck1.2.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Chargen.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_DDoS1.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O3_DDoS2.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O3_DDoS3.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O3_DOMINATE.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O3_EQUINOX.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O3_EvilESP1-1.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_EvilESPV3.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Fud-Bypass.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O3_GHP.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Heartbeat.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Improved SSYN.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_KILLALLv2.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Linux.Dataseg.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Lizzard Stresser.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Massacre.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Netbios.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_OVH-VIP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Prometheus v4.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Quake.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_SSDP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_STCP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_SeCshell.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_Syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_TCP-GEN.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_TS3.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_TriGemini.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_UDP.json
9
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_O3_UFWSIv4.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_bashdoor.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_bluenurse.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_bot.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O3_bot_13.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O3_c7.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O3_client.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_client_1.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_client_16.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O3_client_LizzardSquad.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_client_lulz.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_client_reaper.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O3_client_selfrep.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O3_client_void.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_cnc.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_cnc_13.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O3_csyn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_enemy.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O3_fin.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_fivemovh.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O3_flux.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_O3_game.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_godlyhttp.c_[qbot_client]_lulz.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_O3_hide.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_hide-_19.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_hide_19.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_issyn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_jimmy-sfe.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O3_kaiten.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O3_kgb.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O3_mDNS.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_nova.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O3_oackv1.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O3_oreo.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_oudp.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_10.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_11.json
17
Most common prediction: sparc_uclibc_gcc (Count: 17)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_12.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_17.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_2.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_3.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_4.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_5.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_7.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_8.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_9.json
17
Most common prediction: sparc_uclibc_gcc (Count: 17)
File: ./tmp/sparc-unknown-linux-uclibc_O3_programa_9_1.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O3_psh.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_randomware.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_O3_ranzou-sfe.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O3_reaper_reaper.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_rst.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_rudy.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_O3_server.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_server_1.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_server_16.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_O3_server_LizzardSquad.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_server_selfrep.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_server_void.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_slow.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_O3_start_void.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_stcp.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_sybexv3.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_synopts.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O3_tcp.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_tcp-synack.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_tcp_ack.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_tcp_psh.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_tcp_syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_udpbypass.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_O3_urg.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_xmas.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_O3_yummy.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_50x.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_CFuck1.2.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Chargen.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_DDoS1.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_Os_DDoS2.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_DDoS3.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_DOMINATE.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_EQUINOX.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_EvilESP1-1.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_EvilESPV3.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Fud-Bypass.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_GHP.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Heartbeat.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Improved SSYN.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_KILLALLv2.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Linux.Dataseg.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Lizzard Stresser.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Massacre.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Netbios.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_OVH-VIP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Prometheus v4.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Quake.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_SSDP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_STCP.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_SeCshell.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_Syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_TCP-GEN.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_TS3.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_TriGemini.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_UDP.json
11
Most common prediction: sparc_uclibc_gcc (Count: 9)
File: ./tmp/sparc-unknown-linux-uclibc_Os_UFWSIv4.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_atcp.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_bashdoor.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_bluenurse.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_Os_bogus.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_bot.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_Os_bot_13.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_c7.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_client.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_client_1.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_client_16.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_Os_client_LizzardSquad.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_client_lulz.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_client_reaper.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_Os_client_selfrep.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_client_void.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_Os_cnc.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_cnc_13.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_csyn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_enemy.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_Os_fin.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_fivemovh.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_Os_flux.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_Os_game.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_godlyhttp.c_[qbot_client]_lulz.json
15
Most common prediction: sparc_uclibc_gcc (Count: 15)
File: ./tmp/sparc-unknown-linux-uclibc_Os_hide.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_hide-_19.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_hide_19.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_issyn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_jimmy-sfe.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_kaiten.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_Os_kgb.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_Os_mDNS.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_nova.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_Os_oackv1.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_oreo.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_oudp.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_10.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_11.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_12.json
17
Most common prediction: sparc_uclibc_gcc (Count: 17)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_17.json
11
Most common prediction: sparc_uclibc_gcc (Count: 11)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_2.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_3.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_4.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_5.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_7.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_8.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_9.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_programa_9_1.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_Os_psh.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_randomware.json
13
Most common prediction: sparc_uclibc_gcc (Count: 13)
File: ./tmp/sparc-unknown-linux-uclibc_Os_ranzou-sfe.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_reaper_reaper.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_rst.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_rudy.json
16
Most common prediction: sparc_uclibc_gcc (Count: 16)
File: ./tmp/sparc-unknown-linux-uclibc_Os_server.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_server_1.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_server_16.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_server_LizzardSquad.json
8
Most common prediction: sparc_uclibc_gcc (Count: 8)
File: ./tmp/sparc-unknown-linux-uclibc_Os_server_selfrep.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_server_void.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_slow.json
14
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_start_void.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_stcp.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_sybexv3.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_synopts.json
12
Most common prediction: sparc_uclibc_gcc (Count: 12)
File: ./tmp/sparc-unknown-linux-uclibc_Os_tcp.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_tcp-synack.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_tcp_ack.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_tcp_psh.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_tcp_syn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_udpbypass.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_urg.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_xmas.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_xsyn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc-unknown-linux-uclibc_Os_yummy.json
15
Most common prediction: sparc_uclibc_gcc (Count: 14)
File: ./tmp/sparc-unknown-linux-uclibc_Os_zsyn.json
10
Most common prediction: sparc_uclibc_gcc (Count: 10)
File: ./tmp/sparc64-unknown-linux-gnu_O0_DDoS1.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_DDoS2.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_DDoS3.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_Fud-Bypass.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_Linux.Dataseg.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_Lizzard Stresser.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_Prometheus v4.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_TriGemini.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_bashdoor.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_bluenurse.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_bot.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_bot_13.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_client.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_client_1.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_client_16.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_client_LizzardSquad.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_client_lulz.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_client_reaper.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_client_selfrep.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_client_void.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_enemy.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_flux.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_godlyhttp.c_[qbot_client]_lulz.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_hide.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_hide-_19.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_hide_19.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_jimmy-sfe.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_juno.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_kaiten.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_oreo.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_randomware.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_ranzou-sfe.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_server_16.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O0_yummy.json
22
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_DDoS1.json
20
Most common prediction: sparc_glibc_gcc (Count: 19)
File: ./tmp/sparc64-unknown-linux-gnu_O1_DDoS2.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_DDoS3.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_Fud-Bypass.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_Linux.Dataseg.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_Lizzard Stresser.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_Prometheus v4.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_TriGemini.json
23
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_bashdoor.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_bluenurse.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_bot.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_bot_13.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_client.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_client_1.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_client_16.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_client_LizzardSquad.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_client_lulz.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_client_reaper.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_client_selfrep.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_client_void.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_enemy.json
23
Most common prediction: sparc_glibc_gcc (Count: 21)
File: ./tmp/sparc64-unknown-linux-gnu_O1_flux.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_godlyhttp.c_[qbot_client]_lulz.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_hide.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_hide-_19.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_hide_19.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_jimmy-sfe.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_juno.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_kaiten.json
20
Most common prediction: sparc_glibc_gcc (Count: 19)
File: ./tmp/sparc64-unknown-linux-gnu_O1_oreo.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_ranzou-sfe.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_server_16.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O1_yummy.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_DDoS1.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_DDoS2.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_DDoS3.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_Fud-Bypass.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_Linux.Dataseg.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_Lizzard Stresser.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_Prometheus v4.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_TriGemini.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_bashdoor.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_bluenurse.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_bot.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_bot_13.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_client.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_client_1.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_client_16.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_client_LizzardSquad.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_client_lulz.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_client_reaper.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_client_selfrep.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_client_void.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_enemy.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_flux.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_godlyhttp.c_[qbot_client]_lulz.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_hide.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_hide-_19.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_hide_19.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_jimmy-sfe.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_juno.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_kaiten.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_ranzou-sfe.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_server_16.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O2_yummy.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_DDoS1.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_DDoS2.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_DDoS3.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_Fud-Bypass.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_Linux.Dataseg.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_Lizzard Stresser.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_Prometheus v4.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_TriGemini.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_bashdoor.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_bluenurse.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_bot.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_bot_13.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_client.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_client_1.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_client_16.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_client_LizzardSquad.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_client_lulz.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_client_reaper.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_client_selfrep.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_client_void.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_enemy.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_flux.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_godlyhttp.c_[qbot_client]_lulz.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_hide.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_hide-_19.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_hide_19.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_jimmy-sfe.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_juno.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_kaiten.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_oreo.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_ranzou-sfe.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_server_16.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_O3_yummy.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_DDoS1.json
20
Most common prediction: sparc_glibc_gcc (Count: 19)
File: ./tmp/sparc64-unknown-linux-gnu_Os_DDoS2.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_DDoS3.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_Fud-Bypass.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_Linux.Dataseg.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_Lizzard Stresser.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_Prometheus v4.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_TriGemini.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_bashdoor.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_bluenurse.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_bot.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_bot_13.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_client.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_client_1.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_client_16.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_client_LizzardSquad.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_client_lulz.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_client_reaper.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_client_selfrep.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_client_void.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_enemy.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_flux.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_godlyhttp.c_[qbot_client]_lulz.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_hide.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_hide-_19.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_hide_19.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_jimmy-sfe.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_juno.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_kaiten.json
20
Most common prediction: sparc_glibc_gcc (Count: 19)
File: ./tmp/sparc64-unknown-linux-gnu_Os_oreo.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_ranzou-sfe.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_server_16.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/sparc64-unknown-linux-gnu_Os_yummy.json
21
Most common prediction: sparc_glibc_gcc (Count: 20)
File: ./tmp/x86_64-w64-mingw32_O0_Branko.exe.json
58
Most common prediction: x86_mingw_gcc (Count: 58)
File: ./tmp/x86_64-w64-mingw32_O0_Hunatcha.exe.json
61
Most common prediction: x86_mingw_gcc (Count: 61)
File: ./tmp/x86_64-w64-mingw32_O0_Hunatchab.exe.json
59
Most common prediction: x86_mingw_gcc (Count: 59)
File: ./tmp/x86_64-w64-mingw32_O0_Infector_Win32.MiniPig.exe.json
137
Most common prediction: x86_mingw_gcc (Count: 137)
File: ./tmp/x86_64-w64-mingw32_O0_hide-_19.exe.json
133
Most common prediction: x86_mingw_gcc (Count: 133)
File: ./tmp/x86_64-w64-mingw32_O0_hide.exe.json
130
Most common prediction: x86_mingw_gcc (Count: 130)
File: ./tmp/x86_64-w64-mingw32_O0_hide_19.exe.json
130
Most common prediction: x86_mingw_gcc (Count: 130)
File: ./tmp/x86_64-w64-mingw32_O0_programa.exe.json
132
Most common prediction: x86_mingw_gcc (Count: 132)
File: ./tmp/x86_64-w64-mingw32_O0_server_16.exe.json
134
Most common prediction: x86_mingw_gcc (Count: 134)
File: ./tmp/x86_64-w64-mingw32_O1_Branko.exe.json
57
Most common prediction: x86_mingw_gcc (Count: 57)
File: ./tmp/x86_64-w64-mingw32_O1_Hunatcha.exe.json
60
Most common prediction: x86_mingw_gcc (Count: 60)
File: ./tmp/x86_64-w64-mingw32_O1_Hunatchab.exe.json
61
Most common prediction: x86_mingw_gcc (Count: 61)
File: ./tmp/x86_64-w64-mingw32_O1_Infector_Win32.MiniPig.exe.json
133
Most common prediction: x86_mingw_gcc (Count: 133)
File: ./tmp/x86_64-w64-mingw32_O1_hide-_19.exe.json
135
Most common prediction: x86_mingw_gcc (Count: 135)
File: ./tmp/x86_64-w64-mingw32_O1_hide.exe.json
130
Most common prediction: x86_mingw_gcc (Count: 130)
File: ./tmp/x86_64-w64-mingw32_O1_hide_19.exe.json
130
Most common prediction: x86_mingw_gcc (Count: 130)
File: ./tmp/x86_64-w64-mingw32_O1_programa.exe.json
131
Most common prediction: x86_mingw_gcc (Count: 131)
File: ./tmp/x86_64-w64-mingw32_O1_server_16.exe.json
134
Most common prediction: x86_mingw_gcc (Count: 134)
File: ./tmp/x86_64-w64-mingw32_O2_Branko.exe.json
61
Most common prediction: x86_mingw_gcc (Count: 61)
File: ./tmp/x86_64-w64-mingw32_O2_Hunatcha.exe.json
57
Most common prediction: x86_mingw_gcc (Count: 57)
File: ./tmp/x86_64-w64-mingw32_O2_Hunatchab.exe.json
60
Most common prediction: x86_mingw_gcc (Count: 60)
File: ./tmp/x86_64-w64-mingw32_O2_Infector_Win32.MiniPig.exe.json
135
Most common prediction: x86_mingw_gcc (Count: 135)
File: ./tmp/x86_64-w64-mingw32_O2_hide-_19.exe.json
134
Most common prediction: x86_mingw_gcc (Count: 134)
File: ./tmp/x86_64-w64-mingw32_O2_hide.exe.json
132
Most common prediction: x86_mingw_gcc (Count: 132)
File: ./tmp/x86_64-w64-mingw32_O2_hide_19.exe.json
132
Most common prediction: x86_mingw_gcc (Count: 132)
File: ./tmp/x86_64-w64-mingw32_O2_programa.exe.json
131
Most common prediction: x86_mingw_gcc (Count: 131)
File: ./tmp/x86_64-w64-mingw32_O2_server_16.exe.json
134
Most common prediction: x86_mingw_gcc (Count: 134)
File: ./tmp/x86_64-w64-mingw32_O3_Branko.exe.json
57
Most common prediction: x86_mingw_gcc (Count: 57)
File: ./tmp/x86_64-w64-mingw32_O3_Hunatcha.exe.json
56
Most common prediction: x86_mingw_gcc (Count: 56)
File: ./tmp/x86_64-w64-mingw32_O3_Hunatchab.exe.json
57
Most common prediction: x86_mingw_gcc (Count: 57)
File: ./tmp/x86_64-w64-mingw32_O3_Infector_Win32.MiniPig.exe.json
134
Most common prediction: x86_mingw_gcc (Count: 134)
File: ./tmp/x86_64-w64-mingw32_O3_hide-_19.exe.json
134
Most common prediction: x86_mingw_gcc (Count: 134)
File: ./tmp/x86_64-w64-mingw32_O3_hide.exe.json
132
Most common prediction: x86_mingw_gcc (Count: 132)
File: ./tmp/x86_64-w64-mingw32_O3_hide_19.exe.json
132
Most common prediction: x86_mingw_gcc (Count: 132)
File: ./tmp/x86_64-w64-mingw32_O3_programa.exe.json
133
Most common prediction: x86_mingw_gcc (Count: 133)
File: ./tmp/x86_64-w64-mingw32_O3_server_16.exe.json
134
Most common prediction: x86_mingw_gcc (Count: 134)
File: ./tmp/x86_64-w64-mingw32_Os_Branko.exe.json
57
Most common prediction: x86_mingw_gcc (Count: 57)
File: ./tmp/x86_64-w64-mingw32_Os_Hunatcha.exe.json
56
Most common prediction: x86_mingw_gcc (Count: 56)
File: ./tmp/x86_64-w64-mingw32_Os_Hunatchab.exe.json
57
Most common prediction: x86_mingw_gcc (Count: 57)
File: ./tmp/x86_64-w64-mingw32_Os_Infector_Win32.MiniPig.exe.json
134
Most common prediction: x86_mingw_gcc (Count: 134)
File: ./tmp/x86_64-w64-mingw32_Os_hide-_19.exe.json
137
Most common prediction: x86_mingw_gcc (Count: 137)
File: ./tmp/x86_64-w64-mingw32_Os_hide.exe.json
131
Most common prediction: x86_mingw_gcc (Count: 131)
File: ./tmp/x86_64-w64-mingw32_Os_hide_19.exe.json
131
Most common prediction: x86_mingw_gcc (Count: 131)
File: ./tmp/x86_64-w64-mingw32_Os_programa.exe.json
133
Most common prediction: x86_mingw_gcc (Count: 133)
File: ./tmp/x86_64-w64-mingw32_Os_server_16.exe.json
133
Most common prediction: x86_mingw_gcc (Count: 133)
```