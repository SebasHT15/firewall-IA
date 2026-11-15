# Soporte de TRAIN y errores conocidos del candidato actual

4 de noviembre de 2026. Diagnóstico posterior al experimento Docker del 2 de noviembre. Este conjunto es DEV conocido. Se usó CPU; no se cargó V5, no se entrenó ni se cambió una política del gateway.

## Entradas y comprobaciones

- Artefacto Model2 baseline34: SHA256 `da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38`.
- TRAIN original admitido por Model2: 3080 filas; SHA256 `809ce774cf8d20b4243fcda47d587252d0aa07e4b3e5a6c4619fa222a8fbe745`. No se abrió VALIDATION ni un split protegido.
- Población privada y pública Docker: identidad completa verificada. 540 casos nuevos; los dos casos de regresión conocidos siguen aparte.
- Se verificó por caso el hash canónico, el score portátil frente al score del gateway y el punto experimental 0,9. La reconstrucción baseline reprodujo TP151/TN324/FP48/FN17 observados.
- `DIAGNOSTIC.json` registra hashes de las entradas y del script, términos de `GET /`, errores por componente y escenarios contrafactuales.

## Causa del bloqueo de la raíz

`GET / HTTP/1.1\n` recibe score 0,9999261626310745. Su logit es 9,51357: intercepto +6,36692 y contribución de `symbol_ratio=1` +3,30430. El resto de términos suma aproximadamente −0,15765. La escala TRAIN de `symbol_ratio` es 0,0621143, de modo que el valor 1 es extremo para el ajuste.

TRAIN no contiene ese texto ni otra ruta de menos de 7 caracteres. Su mayor `symbol_ratio` es 0,52866; en ALLOW, 0,36667. `GET /` queda fuera de la cobertura vista al entrenar. Esto explica el score extremo, pero no demuestra una corrección generalizable. El artefacto path-ablation32 produce 0,50527 en la raíz; también cambian intercepto, coeficientes y escalas, por lo que no se atribuye la diferencia únicamente a quitar la longitud/profundidad de la ruta.

## Contrafactual de diferir fuera de soporte

La regla diagnóstica deja que V5 decida cuando un bloqueo temprano de Model2 cae fuera del rango TRAIN de `symbol_ratio` o de longitud de ruta. En estos 540 casos, ambas condiciones identifican exactamente las mismas 15 peticiones `GET /` (un solo texto canónico repetido). Las decisiones V5 ya registradas para ellas son ALLOW.

| Escenario | TP | TN | FP | FN | Bloqueos tempranos TP | Bloqueos tempranos FP | Llamadas a V5 evitadas |
|---|---:|---:|---:|---:|---:|---:|---:|
| Cascada observada baseline34@0,9 | 151 | 324 | 48 | 17 | 24 | 19 | 43/540 |
| Guard de rango, reconstrucción CPU | 151 | 339 | 33 | 17 | 24 | 4 | 28/540 |
| V5 solo observado | 151 | 343 | 29 | 17 | 0 | 0 | 0/540 |

El guard reduce el FPR contrafactual de 12,90 % a 8,87 % en este DEV, frente a 7,80 % de V5 solo. Las 24 detecciones tempranas eran ataques que V5 también bloqueaba; Model2 no recuperó una omisión. Las cuatro FP tempranas restantes son búsquedas benignas con texto internacional, símbolos o apariencia técnica. Este guard reduce ahorro de llamadas de 7,96 % a 5,19 %. No hay medida de gateway, efecto, latencia o capacidad para el guard, ni selección de candidato o umbral.

Los 43 bloqueos tempranos corresponden a 29 textos canónicos únicos. Los 24 ataques bloqueados temprano vienen de cuatro componentes de plantilla (seis SQLi en cada uno de dos componentes y seis SSTI en cada uno de otros dos). Las 19 FP son cinco textos únicos: la raíz repetida 15 veces y cuatro búsquedas de borde. Esto limita la lectura de precisión e incertidumbre por petición.

## Errores de V5.1 que guían nuevos datos

Las 29 FP V5 del conjunto nuevo se reparten en 24 consultas al recurso público de `/fetch` y 5 búsquedas benignas con palabras/símbolos que parecen ataques. Las 17 FN son 12 redirects externos de dos plantillas (`http://` y `https://` con destino externo de laboratorio) y 5 traversal de una plantilla `../private/...`. Cada plantilla tiene variantes de índice, así que los recuentos no son 46 errores independientes. El detalle por componente está en `DIAGNOSTIC.json`.

Antes de entrenar V5 sucesor, construir y sellar cohortes nuevas, con semántica de aplicación comprobada: rutas cortas y sesiones benignas; URL pública frente a SSRF interno; redirects locales permitidos frente a destinos externos; traversal frente a rutas relativas inocuas; búsquedas con lenguaje técnico y Unicode. Separar plantillas/componentes entre ajuste, selección y test. Mantener los casos del Docker actual como regresión conocida. Un cambio de etiquetas para acomodar al modelo invalidaría la comparación.

## Decisión siguiente

1. Repetir este diagnóstico en el DEV anterior y en nuevas cohortes de **selección**, sin escoger el guard usando las 540 filas Docker ya observadas.
2. Diseñar un Model2 sucesor con fuente y receta nuevas, preservando el original; comparar el guard como política de deferencia separada del ajuste ML. Exigir mejora incremental frente a V5 solo y reporte por texto único/sesión, no solo por petición.
3. Diagnosticar `dev-00236` a precisión igual entre nativo y rápido, luego aislar cuantización; no atribuir aún el fallo al decodificador.
4. Fijar candidato y protocolo antes del test final; Sebas decide cualquier apertura de conjunto protegido cuando corresponda. Si Model2 sigue añadiendo falsos bloqueos sin rescatar ataques, presentar V5 solo como resultado de referencia y conservar el resultado negativo de la cascada.

Reproducción: desde la raíz del repositorio, ejecutar `.venv-analyzer/bin/python -m scripts.v5_successor.diagnose_model2_support --output <ruta JSON nueva>`. El script usa `open(..., 'x')` para no sobrescribir evidencia. Requiere el archivo local privado de casos del Docker; no incluye su contenido en el informe.
