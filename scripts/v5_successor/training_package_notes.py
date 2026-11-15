"""Prepare launch/review instructions and test private input recovery, on CPU."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

from successor_contract import REPO,bound,capture,sha


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--recovery',type=Path,required=True);parser.add_argument('--preflight',type=Path);args=parser.parse_args()
    root=args.package.resolve();manifest_path=root/'dataset-manifest.EXPERIMENTAL.json'
    preflight=args.preflight.resolve() if args.preflight else root/'cpu-preflight-1/run_record.json'
    m=json.loads(manifest_path.read_text());pre=json.loads(preflight.read_text())
    if pre['outcome']!='TECHNICAL_REVIEW_PASSED_PENDING_OWNER_AND_COMMIT':raise ValueError('CPU preflight incomplete')
    if pre['manifest_sha256']!=sha(manifest_path.read_bytes()):raise ValueError('Preflight belongs to other manifest')
    if args.recovery.exists() or (root/'README.md').exists():raise ValueError('Do not overwrite prepared delivery')
    files={Path(d['path']) for d in m['artifacts']}
    files.update(Path(d['path']) for group in m['augmentation'].values() for d in group.values())
    parent=Path(m['parent']['dataset_dir'])
    files.update(parent/name for name in ['rows.TRAIN.jsonl','rows.TRAIN.meta.jsonl'])
    inputs={str(p.resolve()):bound(p) for p in sorted(files)}
    # Source/preview reserve artifacts are deliberately absent. Metadata about
    # their predeclared hashes does not require opening their contents.
    if any('RESERVE' in p.name or 'INTERNAL_TEST' in p.name for p in files):raise ValueError('Protected input in recovery list')
    args.recovery.parent.mkdir(parents=True,exist_ok=True)
    unique={d['sha256']:Path(d['path']) for d in inputs.values()}
    with tarfile.open(args.recovery,'x:gz',compresslevel=4) as tar:
        for digest,path in sorted(unique.items()):tar.add(path,arcname='blobs/'+digest,recursive=False)
    args.recovery.chmod(0o600)
    restored=0
    with tempfile.TemporaryDirectory(prefix='v51-recovery-check-',dir=args.recovery.parent) as temp:
        with tarfile.open(args.recovery,'r:gz') as tar:
            for digest in unique:
                member=tar.extractfile('blobs/'+digest)
                if member is None:raise ValueError('Missing retained input')
                path=Path(temp)/digest;path.write_bytes(member.read())
                if sha(path.read_bytes())!=digest:raise ValueError('Recovery hash mismatch')
                restored+=1
    retention=dict(scope='New composition inputs plus original TRAIN only; original parent audit pools and base model follow existing retention procedures',
                   archive=bound(args.recovery),files=inputs,restored_unique_blobs=restored,
                   recovered_hashes_match=True,reserve_opened=False,weights_included=False)
    (root/'DATA_RETENTION.json').write_text(json.dumps(retention,indent=2)+'\n')
    required={str(Path(m['manifest_path']).resolve()),m['recipe']['path'],m['protocol']['path'],
              str(root/'owner-admission.DRAFT.json')}
    required.update(d['path'] for d in m['evidence'].values())
    required.update(str(REPO/p) for p in m['source_sha256'])
    required.update(str(REPO/p) for p in ['scripts/v5_successor/training_package_notes.py','tests/test_v51_successor_training.py'])
    required.update(str(root/name) for name in ['README.md','DATA_RETENTION.json','composition-check.json'])
    tracked=set(subprocess.check_output(['git','ls-files','-z'],cwd=REPO).decode().split('\0'))
    dirty=set(subprocess.check_output(['git','diff','--name-only','HEAD','-z'],cwd=REPO).decode().split('\0'))
    commit_paths=[]
    for name in sorted(required):
        path=Path(name)
        if not path.is_relative_to(REPO):raise ValueError('Non-repository approval/code path')
        rel=str(path.relative_to(REPO))
        if rel not in tracked or rel in dirty:commit_paths.append(rel)
    (root/'COMMIT_PATHS.json').write_text(json.dumps(dict(status='OWNER_ACTION_ONLY_NOT_STAGED',
        paths=commit_paths,note='Add the separate APPROVED admission file chosen by the owner. Private row/source files stay out of Git. This list does not select or discard Claude files.'),indent=2)+'\n')
    rel=lambda p:str(Path(p).relative_to(REPO))
    readme=f'''# Paquete V5 sucesor — revisión del 31 de octubre de 2026

Preparación técnica terminada. No se entrenó ningún modelo y no se utilizó la GPU de Claude.

TRAIN tiene 5.166 filas (2.583 ALLOW y 2.583 BLOCK): conserva literalmente el prefijo de 3.080 filas originales y añade 2.086 filas URL. VALIDATION tiene 2.080 filas nuevas, balanceadas. La comprobación CPU tokenizó las 7.246 filas sin rechazar ni truncar ninguna; máximo 406/512 tokens, B415, overhead76 y presupuesto de salida de13 tokens incluido EOS. Fuente TRAIN:86 registros/18 componentes; validación18 registros/15 componentes. Las filas no son observaciones independientes.

La receta propone cuatro épocas, batch efectivo32,648 pasos y evaluación/guardado cada162 pasos. Parte de la base TinyLlama fijada con una LoRA nueva; no continúa entrenando el adaptador V5 existente. Los pesos anteriores y todas las categorías originales se conservan.

## Qué significa la admisión

Esta entrega propone una composición EXPERIMENTAL versionada: hereda únicamente el TRAIN del padre congelado, verifica su auditoría original y añade URLs cuya etiqueta deriva de las políticas D62/D75. La admisión H1 acotada de fuentes nuevas debe aceptarse expresamente; no se inventa un PASS_AI_AUDITED para esas URLs. El lector FINAL anterior permanece intacto y no se presenta este paquete como FINAL.

El propietario debe revisar y adoptar este protocolo experimental antes de entrenar. El registro owner-admission.DRAFT.json permanece deshabilitado. Para aprobarlo después de revisar ambas entregas, crear un archivo separado owner-admission.APPROVED.json con los mismos hashes; cambiar status a APPROVED_EXPERIMENTAL, training_allowed y accept_scoped_policy_sources a true, y completar owner_decision, authorized_by y date con una referencia y datos reales del propietario. No inventar una decisión Dxx. Solo Sebas hace el commit de ese registro y de los archivos revisados.

COMMIT_PATHS.json enumera los archivos propios pendientes, sin hacer staging ni seleccionar cambios de Claude. Los datos crudos permanecen privados, ligados por hash. Antes de ejecutar, el lector exige que autorización, manifiesto, receta, protocolo, evidencia y fuentes estén comprometidos y sin cambios. El commit por sí solo no aprueba un DRAFT.

## Comandos preparados

Desde /home/sebas/Desktop/firewall-IA, usar un directorio de reporte NUEVO en cada comando. La revisión se puede ejecutar con GPU ocupada:

    /usr/bin/python3.12 -B scripts/v5_successor/train_successor.py --mode review --manifest {rel(manifest_path)} --report-dir {rel(root)}/review-NUEVA

Después de la aprobación y el commit del propietario, verificar permisos y todos los ejemplos sin cargar pesos:

    /usr/bin/python3.12 -B scripts/v5_successor/train_successor.py --mode gate --manifest {rel(manifest_path)} --authorization {rel(root)}/owner-admission.APPROVED.json --report-dir {rel(root)}/gate-NUEVO

Solo cuando Claude libere la GPU, iniciar el experimento:

    /usr/bin/python3.12 -B scripts/v5_successor/train_successor.py --mode train --manifest {rel(manifest_path)} --authorization {rel(root)}/owner-admission.APPROVED.json --report-dir {rel(root)}/training-NUEVO --run-id v51-policy-EXPERIMENTO-NUEVO

La salida se guarda en model-output-v5/experimental/ con un nombre exclusivo. El lanzador rechaza un nombre existente, una GPU reservada por Claude o procesos GPU ajenos. No hay modo FINAL ni opción para saltar permisos. Reutiliza el fitting, las máscaras de pérdida, el guardado y la recarga del entrenador existente, con un acceso nuevo explícito para esta composición.

## Qué revisar al terminar

Medir etiquetas y motivos por separado, salidas inválidas y denegación efectiva, por política/carrier/familia/componente. Comprobar no regresión en las categorías originales y benignos DEV; no convertir errores conocidos en evaluación independiente. Conservar los conjuntos protegidos fuera del desarrollo. La validación nueva mide políticas URL del proyecto, no explotación universal de una aplicación.

No se promete resolver JWT/CSRF sin estado/cabeceras ni CMD en JSON, que necesita una compatibilidad versionada. ALT_A tiene salidas NoSQL/XPath/CRLF sin ejemplos en este experimento; no atribuirles cobertura. Las nuevas pesas y vocabulario requieren volver a verificar NF4 y verified-suffix; el perfil rápido actual está ligado al adaptador viejo y no sirve para promover automáticamente el nuevo.

## Evidencia y recuperación

composition-check.json registra la composición; {rel(preflight)} contiene los tokens, versiones y calendario reales. expected-refusal-draft/run_record.json conserva el rechazo esperado del DRAFT antes de abrir filas para entrenamiento.

DATA_RETENTION.json contiene el archivo privado de recuperación, hashes e índice de diez rutas de entrada. Se restauraron sus blobs en una carpeta temporal y se verificaron todos los hashes. No contiene reservas, pesos ni los pools de auditoría antiguos: estos últimos conservan sus procedimientos de retención originales. No se redistribuyen filas crudas en esta entrega.
'''
    (root/'README.md').write_text(readme)
    status=json.loads(Path('/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura/GPU_STATUS.json').read_text())
    readiness=dict(status='TECHNICALLY_PREPARED_FOR_OWNER_REVIEW_NOT_YET_AUTHORIZED_TO_TRAIN',
                   manifest=bound(manifest_path),CPU_preflight=bound(preflight),
                   training_started=False,owner_admission_approved=False,
                   files_pending_owner_commit=len(commit_paths),GPU_owner_at_preparation=status.get('owner'),
                   launch_conditions=['Adopt the exact experimental composition and scoped source admission',
                                      'Owner commits approved authorization and bound records/code',
                                      'Claude releases GPU; gate command passes'],
                   recovery_hashes_verified=True,reserve_opened=False)
    (root/'READINESS.json').write_text(json.dumps(readiness,indent=2)+'\n')
    print(json.dumps(readiness,indent=2))


if __name__=='__main__':main()
