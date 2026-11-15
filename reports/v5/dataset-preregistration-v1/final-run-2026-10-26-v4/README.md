# v4 — dataset y entrenadores preparados

Manifest: c2e9c2f50f56c059ce82945384858802357be88d899dc2710e20edd06a2b72df. 3080 TRAIN + 40 VALIDATION + 40 INTERNAL_TEST; 1580 pares.

D78 autoriza completar la preparación; D79 registra el freeze, D80 V5 ai-audited y D81 los dos candidatos Model2. Fuente: instrucción exacta del propietario en el chat, sin firmas inventadas ni validación humana atribuida. Los entrenamientos NO se ejecutan como parte de esta preparación.

H1 y demás controles bloqueantes pasan. A2 v4 reproduce manifest+14 artefactos en procesos/semillas/CWD distintos y árbol limpio. Se preservan v3, sus hallazgos y STAB-HELD. Los splits protegidos de v4 son byte-idénticos a v3. Doce payloads y un valor benigno con identidad no permitida se excluyen en fuentes; los demás registros mantienen bytes y pertenencia a sus componentes originales, separados.

Evidencia de entrada inicial: reports/v5/training-readiness/final-ready-2026-10-26-v4/. V5 pasó gates+tokenización: 3080/40, 0 rechazados, 0 truncados, secuencia máxima406/512. Model2 baseline y ablación pasaron FINAL_GATES_PASSED con trained=false. Las verificaciones finales de HEAD se guardan también como entregables en el chat.

El preflight de metadatos tiene env_ready=true; su ready_to_launch=false es deliberado porque no lee filas. La evidencia de preparación completa es el gate real del trainer, que sí pasó. GPU RTX4090 Laptop, bibliotecas y cache local verificadas; no se cargaron pesos para entrenar.

## Comandos del propietario

Desde cualquier directorio:

```bash
bash /home/sebas/Desktop/firewall-IA/reports/v5/dataset-preregistration-v1/final-run-2026-10-26-v4/Entrenar_Model2.sh
bash /home/sebas/Desktop/firewall-IA/reports/v5/dataset-preregistration-v1/final-run-2026-10-26-v4/Entrenar_V5.sh
```

Cada script comprueba árbol limpio, PR a develop (D73) y gates antes de ajustar. Model2 ejecuta los dos candidatos, cada uno con su autorización. No se selecciona umbral operativo ni se despliega un ganador. V5 usa la receta FINAL ratificada, no un smoke.

## Límites

Cuatro categorías son TRAIN-only/NOT_EVALUABLE; solo path_file_access tiene evaluación, con concentración declarada. L10 WARN alto, STAB concept-built, limitaciones PATT y AI_AUDITED≠validación humana permanecen. Los archivos locales de fuentes/dataset están ignorados por Git y conservados con hashes/recuperación, sin garantía de backup off-device. Preparación no significa éxito de entrenamiento o rendimiento de producción.
