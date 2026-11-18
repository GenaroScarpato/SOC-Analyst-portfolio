# T1-07 · Más de 1 GB copiado a una memoria USB

**Veredicto:** Verdadero positivo · **Acción:** Escalar a N2 · **MITRE:** T1052.001 (Exfiltration Over Physical Medium: Exfiltration over USB)

## Alerta
Se copia a un USB un volumen superior a 1 GB desde un recurso compartido de Finanzas.

## Evidencia clave
```text
11:58:12 edr device host=PC-ALM-014 user=a.garcia type=USBSTOR vendor='SanDisk' serial=4C5310 mounted=E:
12:01:30 win-SRV-FS01 EventID=5145 ShareName=\\SRV-FS01\Finanzas RelativeTargetName=Nominas\2026 SubjectUserName=a.garcia IpAddress=10.20.2.14 AccessMask=0x1
12:03:51 edr file_copy host=PC-ALM-014 user=a.garcia src=\\SRV-FS01\Finanzas\Nominas\2026 dst=E:\ files=412 bytes=1.21GB
12:04:10 ad a.garcia department=Almacen groups=GG_Almacen,GG_Finanzas_Lectura(added 2026-03-02, ticket REQ-1180 'acceso temporal inventario')
```

## Análisis
- Se confirma una copia real de 412 archivos (1,21 GB) de la carpeta de nóminas a un USB SanDisk.
- El usuario pertenece a Almacén y tiene permiso de lectura sobre Finanzas por el ticket REQ-1180, solicitado para consultar inventario.
- Ese permiso permite leer, pero no hay autorización específica para extraer nóminas a un dispositivo externo.
- No se puede afirmar todavía una intención maliciosa, pero existe riesgo de fuga de información.

## Decisión
Verdadero positivo. Se escala a N2 para investigar una posible fuga de datos. Ver el [informe de relevo](informe-relevo-T1-07.md).
