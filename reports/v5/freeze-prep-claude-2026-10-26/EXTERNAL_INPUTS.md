# Insumos externos — conservación ejecutada, sin redistribución

Se preservaron los originales y se creó una copia local verificable. No se movieron ni alteraron los pools originales.

| Insumo | SHA fijado |
|---|---|
| pilot-pools manifest | 375f3d2b415ab5e78606d88b4b15371f02580d1d469aa0dc60bebaa643b56f09 |
| benign pools manifest | 48474e3bf7adf868eea95f20337e406601624b1442bbc7c533f50f4fccf9bd0d |
| assembled attack pool | 4d43e0bf190e6b08b9fb0828ae20aa4c17f9eef849b149389a00abc035ae0c39 |
| PATT clone commit | e961fef231d8327bae83b563fab50aec2e6b77c0 |

Archivo retenido: `/home/sebas/Desktop/firewall-IA/datasets/v5_sources/freeze_input_retention_2026-10-26/inputs.tar.gz`
SHA-256 del archivo: `e8f58bd4396f347f7d7ac86dba1039dbea60f827929fd6d5b20c16fb8cc26eed`
Tamaño: 9333357 bytes. Incluye pools construidos, benignos, ataque ensamblado, pool original de auditoría y licencia PATT.
Inventario de 18 archivos con sus paths de origen, rutas de recuperación, tamaños y SHA en `external-input-retention.json`.

## Recuperación verificada

El script `retain_external_inputs.py` creó el archivo, extrajo una copia en un directorio temporal y verificó SHA y tamaño de los 18 archivos.
No se generó un dataset ni se repitió A2. Para recuperar: verificar el hash del tar, extraer en un directorio nuevo y comprobar cada miembro contra el inventario.
Usar las copias recuperadas como rutas explícitas --pilot-pools/--benign-pools/--attack-pool cuando se autorice un build; no sobrescribir los originales.

Python requerido para identidad del manifest: 3.14.4; ejecutable y SHA capturados en el inventario.
PATT puede recuperarse desde https://github.com/swisskyrepo/PayloadsAllTheThings.git usando el commit fijado para revisar los originales;
el pool ensamblado exacto está retenido localmente. Persisten las limitaciones A4 de 1666 filas legacy sin SHA individual.

## Límites

La copia está en el mismo equipo: no se verificó un backup independiente ni protección ante pérdida física del disco.
El ejecutable Python está identificado; no se afirma una imagen autocontenida portable con todas sus bibliotecas del sistema.
No se redistribuyeron datos de terceros. CSIC no está incluido. Las rutas/huellas originales se conservan en los manifests y el inventario.
