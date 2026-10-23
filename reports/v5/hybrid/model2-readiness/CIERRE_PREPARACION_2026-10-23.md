# Cierre del lote C1 / Model 2 / intercambio V5

**Estado: lote de preparación terminado y verificado para commit y PR a develop.**
Rama: `feat/hybrid-training-integration`. Base:
`7ee8570830f6e9bfaa3edfa381ca430693e911f4` (D70, PR #86 ya fusionado en develop).
El owner conserva commit/push/PR/merge. No se creó un commit nuevo al reconciliar.

## Pendientes del lote resueltos

| Punto | Resolución | Evidencia |
|---|---|---|
| B: piloto autorizado | Corregidas las dependencias #77/#82, política/configuración y ruta fixture-only; tokenización verificada antes del piloto. Tres constantes no autorizan un build. | Paquete B §2.1, §3 y §5, contrastado con spec y generador |
| B: F10 completo | Incluye los dos hashes de binding, las dos aceptaciones booleanas, autor/fecha/decisión, registro separado/commiteado y rechazo mientras el esquema sea inerte; consumidores diferenciados. | B §2.6, contrastado con el parche #80 |
| Candidatos exactos | Instrucción y siete outputs literales, receta JSON íntegra y 11 SHA-256 completos de fuentes. | Comparación literal/JSON y comprobación de hashes, sin divergencias |
| A: alcance wire | Comparación de hops declarada diagnóstico complementario; sin exclusividad ni promoción automática a VERIFIED. Preservación funcional y medición de coste separadas. | Propuesta A §3–§5 |
| Base de integración | Fast-forward desde 478524d a develop/D70 7ee8570; los 42 archivos locales anteriores conservaron sus bytes. | Comparación de SHA-256 antes/después; sin conflictos ni commit nuevo |
| Pruebas tras reconciliar | 56 data-plane + 26 analyzer pasan, cero fallos/errores/skips. | Dos invocaciones exactas indicadas debajo |

## Verificación final ejecutada

```sh
.venv-dataplane/bin/python -B -m unittest tests.model2.test_contracts tests.model2.test_c1_readiness tests.model2.test_evaluation tests.model2.test_c1_extensions tests.model2.test_grouped_evaluation tests.model2.test_identity_groups
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 .venv-analyzer/bin/python -B -m unittest tests.model2.test_path_ablation tests.model2.test_grouped_fixture_experiment tests.model2.test_fixture_experiment tests.model2.test_v5_fixture_integration
```

**82 pruebas aprobadas sobre la base D70.** Los tests generan sus propios fixtures;
no abren datasets reales/protegidos. La integración compartida verifica 232 TRAIN /
24 VALIDATION; al unir identidades hay 4/1 componentes. Todos los intervalos de
VALIDATION quedan nulos por insuficiencia de grupos. No hay variante seleccionada.

Los reportes `grouped-fixture-experiment-v1.json` y `c1-extension-evidence-v2.json`
conservan sus hashes originales; sus 25 y 5 fuentes, respectivamente, coinciden
con las fuentes actuales. La nueva corrida de tests se registra aquí; no se
presenta una evidencia histórica como si hubiera sido regenerada en esta base.
El lector previamente cerrado conserva sus hashes y evidencia de 44 pruebas
anteriores; no se repitió ni reabrió esa auditoría. No se repitió el lab TCP D70.

## Alcance terminado

Contratos y extracción C1 offline, lector/intercambio V5, integración de fixtures,
learner efímero, ablación del path, agrupación y diagnóstico de incertidumbre,
pruebas y reportes A/B corregidos. No hay correcciones pendientes de este alcance.
Los documentos anteriores de model2-readiness conservan sus checkpoints históricos;
este cierre y el encabezado actual del README prevalecen para el estado presente.

El runtime y la configuración coinciden con D70; V4 sigue siendo la única autoridad.
El cambio al trainer es el parser compartido de filas con preservación de Unicode;
no activa r4. C1 nuevo sigue fuera de los inputs aprendidos. No se guardan pesos.

## Trabajo posterior en ramas nuevas desde develop

1. **#80:** contrato de procedencia, estados de fila y autorización ratificados;
   implementar la migración del trainer y verificar gates. La propuesta actual
   no activa el contrato por sí sola.
2. **#77 y #82:** resolver auditoría/decisiones de categorías y demás entradas;
   ejecutar el piloto real aprobado, gates y preregistro; construir y verificar
   los datos destinados al entrenamiento.
3. **Entrenamiento:** V5 y Model 2 son modelos separados, con recetas y
   evaluación propias sobre datos elegibles. C1 es determinista; C2 está fuera
   de esta primera versión.
4. **Integración híbrida:** preparar interfaces, delegación, fallos y modo sombra
   con dobles de modelos antes de disponer de pesos; después medir la cadena con
   los modelos reales. El control wire, B/Limits y la política positiva siguen
   como requisitos de Fast Path. Despliegue/activación requieren la verificación
   del conjunto, no solo completar el entrenamiento.

Este orden acelera la preparación sin declarar autorizados datos, criterios de
riesgo o políticas que aún requieren decisiones. Las tareas futuras no se
confunden con pendientes de este PR de preparación.
