# Informe de relevo SOC · T1-07

**Incidente:** Copia masiva de información a dispositivo USB
**Prioridad:** Media
**Estado:** Escalado a N2
**Equipo afectado:** PC-ALM-014

## 1. Descripción del incidente

El EDR detectó la conexión de un dispositivo USB SanDisk al equipo PC-ALM-014 y una posterior copia masiva de información desde el recurso compartido de Finanzas.

La operación involucró 412 archivos y un volumen total de 1,21 GB.

## 2. Datos relevantes

- **Usuario:** a.garcia
- **Departamento:** Almacén
- **Equipo:** PC-ALM-014
- **Dispositivo:** USB SanDisk
- **Carpeta de origen:** `\\SRV-FS01\Finanzas\Nominas\2026`
- **Volumen transferido:** 1,21 GB
- **Archivos copiados:** 412
- **Ticket relacionado:** REQ-1180
- **MITRE ATT&CK:** T1052.001 – Exfiltration Over Physical Medium: Exfiltration over USB.

## 3. Evidencias recopiladas

- **Conexión del dispositivo USB** (EDR).
- **Acceso a la carpeta de nóminas de Finanzas** (servidor de ficheros).
- **Copia de 412 archivos hacia la unidad E:** (EDR).
- **Pertenencia a Almacén con permisos de lectura temporal sobre Finanzas** mediante REQ-1180 (Active Directory).

## 4. Análisis y evaluación

Se confirma una transferencia real de información sensible hacia un dispositivo externo.

Aunque el usuario dispone de permisos de lectura sobre Finanzas, no se encontró evidencia de una autorización específica para copiar información de nóminas a un USB.

No se puede confirmar todavía una intención maliciosa, pero existe riesgo de fuga de información.

## 5. Clasificación y acción

- **Veredicto:** Verdadero positivo.
- **Acción:** Escalar a N2.
- **Motivo:** posible extracción no autorizada de información sensible.

## 6. Acciones pendientes para N2

1. Validar con el responsable de Finanzas si la copia estaba autorizada.
2. Revisar el contenido y la sensibilidad de los archivos extraídos.
3. Identificar el número de serie del USB y determinar quién lo controla.
4. Revisar otras transferencias realizadas por a.garcia.
5. Evaluar la necesidad de bloquear el dispositivo y preservar las evidencias.
6. Determinar si corresponde activar el procedimiento de respuesta ante fuga de información.

## 7. Conclusión

Se entrega el incidente a N2 para continuar la investigación de una posible fuga de información. La copia masiva está confirmada, pero todavía debe determinarse si fue autorizada y si existió exposición de datos personales o confidenciales.
