# `dev-00236`: cuantización y decodificador separados

4 de noviembre de 2026. Diagnóstico de un caso **legacy DEV conocido**, no estimación de calidad, tasa de inválidos ni equivalencia universal. Se usó el adaptador V5.1 existente, sin entrenamiento ni cambios de pesos, receta, vocabulario o decoder. Tres repeticiones por configuración en la misma PC/GPU. Entrada canónica SHA256 `445f6d7d1dd6d690b19cc37a7f69a77eb47d37a354671bd78623950fb57da1f3`.

| Cuantización | Decodificador | Salida en 3/3 | Estado | Motivo |
|---|---|---|---|---|
| NF4 con doble cuantización, receta | Greedy nativo | `BLOCK \| Cross-site scripting payload detected.` | parseable, BLOCK | Razón incorrecta para la referencia XXE |
| NF4 sin doble cuantización, perfil experimental | Greedy nativo | `BLOCK \| Entity injection payload detected.` | inválido `not_in_vocabulary` | La cadena no está en las 12 salidas permitidas |
| NF4 sin doble cuantización, mismo modelo cargado | Sufijo verificado | `BLOCK \| Entity injection payload detected.` | inválido `not_in_vocabulary` | Verificación falló y regresó a generación nativa |

Las tres repeticiones de cada configuración tuvieron la misma firma y hash de texto. El perfil sin doble cuantización cargó `double_quant=false`; la receta cargó `double_quant=true`. El sufijo verificado y el greedy nativo compartieron **la misma instancia cargada** en NF4 sin doble cuantización. Sus salidas coincidieron exactamente; el sufijo usó fallback. La diferencia observada al cambiar de cuantización, con decoder nativo constante, apoya atribuir **este caso** a la cuantización. No hay evidencia aquí de que el decoder sea la causa de este inválido.

Operativamente la salida inválida se deniega por fail-closed; no se cuenta como un acierto del clasificador. La salida parseable con doble cuantización bloquea, pero da la razón XSS para una referencia histórica XXE fuera del vocabulario actual. El texto `Entity injection` tampoco forma parte del vocabulario V5.1. Esto pone el foco en vocabulario/cobertura de categorías y estabilidad de la generación, no en forzar etiquetas mediante el decodificador.

`DIAGNOSTIC.json` conserva salida exacta, hash, perfil cargado, identidad de entradas y código, y los nueve resultados. El script `scripts/v5_successor/diagnose_dev236.py` verificó identidad canónica, estado y procesos GPU antes de cargar; liberó la GPU al terminar. Al cierre, `GPU_STATUS.json` volvió a `AVAILABLE` y `nvidia-smi` mostró solo el terminal gráfico.

**Siguiente decisión de diseño:** incluir casos fuera del vocabulario de razones en una cohorte de desarrollo explícita. Evaluar BLOCK/ALLOW y cobertura de razón por separado; mantener invalid como categoría propia. Cualquier cambio de vocabulario requiere receta/adaptador sucesor y nueva medición, sin editar V5.1 histórico ni usar este caso para estimar desempeño general.
