# Fast Path activo: integración con seis aplicaciones

5 de noviembre de 2026. Este informe responde al estado del bloque Fast Path del diagrama de arquitectura. El stack de seis apps lo tenía apagado por configuración; el router y el control de framing ya implementaban `FAST_ALLOW`. Se añadió una variante **experimental de laboratorio** del brazo `guarded`, con una política positiva por app para un único recurso estático exacto del commit `be8e4e8f1c6aa12a17430146d569870d96d43dd5`. El brazo `guarded` original permanece como control sin Fast Path. No se cambió ninguna aplicación ni ningún peso de Model 2 o V5.1.

| Aplicación | GET estático permitido | Resultado | Query `?x=1` |
|---|---|---|---|
| An0nB0ard | `/static/css/style.css` | `FAST_ALLOW`, 200 | `CONTINUE` → V5 doble |
| CatP1cs | `/static/img/favicon.ico` | `FAST_ALLOW`, 200 | `CONTINUE` → V5 doble |
| D33pTh0ught | `/static/img/machine.jpg` | `FAST_ALLOW`, 200 | `CONTINUE` → V5 doble |
| Inf3ct | `/static/img/anon.png` | `FAST_ALLOW`, 200 | `CONTINUE` → V5 doble |
| ObC00ki3s | `/static/js/cks.js` | `FAST_ALLOW`, 200 | `CONTINUE` → V5 doble |
| ag3ncy | `/static/img/avatar.png` | `FAST_ALLOW`, 200 | `CONTINUE` → V5 doble |

Los seis smokes completos pasaron (67/67 checks en total). En cada `FAST_ALLOW`, el registro muestra `deciding_stage=fast_path`, `model2=null`, `v5=null` y recepción en la app. La política exige `GET`, `Host` exacto, recurso exacto, ausencia de query/cuerpo/cabeceras extra, canonicalización aceptada y framing `EGRESS_BOUND` verificado por petición. Una variante con query no tomó el bypass. La limpieza pasó en las seis corridas. Se usó V5 **doble** y auditoría de Fast Path al 0 % para atribuir la decisión sin una llamada de auditoría asíncrona a V5.

La primera corrida de ObC00ki3s tuvo 10/12 checks porque el harness tomó un evento de entrega como último veredicto; el log ya contenía `FAST_ALLOW`. Se corrigió la selección de filas `kind=decision`, se conservó esa evidencia y la repetición pasó 12/12. No fue un fallo de la cascada.

Esto demuestra un Fast Path **activo** y estrecho en las seis apps. No demuestra seguridad de rutas dinámicas, tasa de bypass, reducción de latencia ni acuerdo estadístico con V5.1 real. Antes de usarlo en una medición, se debe congelar la política y el contrato de cada app, decidir una tasa de auditoría, separar la carga de auditoría y medir cualquier ataque que una regla pudiera dejar pasar. C2 es evidencia aprendida opcional de un Analyzer anterior que permanece en sombra; el Model 2 actualmente seleccionado usa las 34 variables C1 directamente, por lo que C2 no es una etapa requerida de esta cascada.

Una sonda posterior con **V5.1 real** en ObC00ki3s comprobó el salto entre etapas: `GET /static/js/cks.js` recibió 200 por `FAST_ALLOW` sin invocar Model 2 ni V5.1, y `GET /` recibió 200 tras `CONTINUE` → Model 2 `DEFER` → V5.1 `ALLOW`. `real-v51-ObC00ki3s/RESULT.json` fija el manifiesto, política y decisiones; `CLEAN.json` es `clean: true`, Docker quedó vacío y la GPU volvió a `AVAILABLE`. Es una prueba de integración de dos peticiones, no un resultado de calidad.
