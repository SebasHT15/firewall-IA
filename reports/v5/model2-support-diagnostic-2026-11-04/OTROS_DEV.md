# Contraste del guard de soporte en otros DEV conocidos

4 de noviembre de 2026. Todos los recuentos son diagnósticos posteriores sobre poblaciones ya observadas. No se elige una política con ellos. El score portable baseline34 reprodujo los 434 scores de gateway de la comparación V5.1.

## DEV authored de 434 casos con V5.1 nativo

La cascada baseline34 observada da TP195/TN214/FP7/FN18. Un guard de `symbol_ratio` basado en el máximo de TRAIN no cambia ninguna de esas decisiones ni los bloqueos tempranos: 51 TP y 1 FP. Un guard de longitud mínima de ruta difiere tres ataques que Model2 bloqueaba; V5 también los bloqueó, por lo que la matriz final no cambia, pero las llamadas V5 evitadas bajan de 52 a 49. No elimina la FP temprana. El guard combinado tiene el mismo efecto que el de longitud.

## Legacy DEV canónico aceptado de 578 casos

Solo se cuentan bloqueos tempranos de Model2; no hay una corrida V5.1 emparejada sobre los 578 casos en esta comparación. Las referencias históricas de este conjunto tienen límites de procedencia y no se presentan como verdad validada de ataques.

| Escenario CPU | Bloqueos tempranos de referencia BLOCK | Bloqueos tempranos de referencia ALLOW | Ataques antes tempranos ahora diferidos |
|---|---:|---:|---:|
| baseline34@0,9 | 117 | 8 | 0 |
| guard de longitud | 104 | 8 | 13 |
| guard de proporción de símbolos | 112 | 8 | 5 |
| ambos | 99 | 8 | 18 |

Las condiciones que ayudan a `GET /` no eliminan ninguna de las ocho FP tempranas de este legacy DEV. Por tanto, el guard explica una mitigación local, pero no ofrece evidencia suficiente para adoptarlo como política general. Model2 sigue necesitando datos/representación sucesores y selección con cohortes nuevas. Si no demuestra beneficio incremental sobre V5 solo, el resultado final debe mostrarlo sin ocultarlo con una excepción de ruta.

Entradas: `reports/v5/hybrid/gateway-integration-v1/candidate-trials-2026-11-01/compare-native/rows-*.jsonl`, el archivo privado `inputs.private.jsonl` del experimento del 30 de octubre y los mismos pesos baseline34. Solo se leyeron DEV conocidos y el TRAIN original para definir los límites; no se abrieron conjuntos protegidos.
