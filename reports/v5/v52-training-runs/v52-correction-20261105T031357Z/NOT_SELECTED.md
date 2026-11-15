# V5.2 no seleccionado

Decisión del propietario, 5 de noviembre de 2026: continuar con V5.1. El entrenamiento V5.2 se conserva como evidencia experimental; sus manifiestos y configuraciones de `delivery/` no deben usarse para la evaluación siguiente.

El censo completo de VALIDATION produjo 2290/2290 salidas válidas. En las 2080 filas originales, V5.1 tenía TP 1040, FN 0, TN 1036, FP 4; V5.2 tuvo TP 1027, FN 13, TN 1040, FP 0. Corrigió cuatro FP pero introdujo 13 FN. En las 210 filas nuevas, V5.2 tuvo TP 75, FN 15, TN 120, FP 0. Los 15 FN nuevos pertenecen a una plantilla de redirect abierto; la otra plantilla BLOCK se clasificó como SSRF, con motivo incorrecto en sus 15 filas.

Estas son cifras de validación de desarrollo, no tráfico real ni prueba independiente. `training/census-analysis.json` y `training/parent-paired-v51.json` contienen los recuentos y hashes. Se mantiene el adaptador para reproducibilidad, sin selección ni despliegue.
