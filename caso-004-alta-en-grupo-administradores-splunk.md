# Caso 004 — Detección de alta en Administradores locales con Splunk

**Categoría:** Gestión de cuentas / cambio de privilegios  
**Severidad potencial:** Alta si el cambio no está autorizado  
**Plataforma:** Windows Security Event Log, Splunk Universal Forwarder y Splunk Cloud  
**Resultado del laboratorio:** detección correcta de una actividad autorizada; respuesta simulada y limpieza verificadas

## Resumen ejecutivo

En un laboratorio propio generé un cambio controlado de membresía en el grupo local **Administradores** usando una cuenta temporal deshabilitada. El Universal Forwarder envió los eventos de Windows Security a Splunk Cloud. Analicé la secuencia con SPL y configuré una alerta programada cada cinco minutos para detectar el evento **4732** cuando el grupo objetivo es Administradores.

La alerta se disparó a las **02:26:45 UTC**, luego del evento registrado a las **02:23:31 UTC**. Validé el actor, el equipo, el grupo y el SID de la cuenta. Finalmente retiré la cuenta temporal del grupo y la eliminé; PowerShell confirmó que ya no figuraba ni en el grupo ni como usuario local.

**Clasificación:** verdadero positivo de la regla — ocurrió el cambio que la detección debía encontrar. **Veredicto de seguridad:** actividad benigna y autorizada del laboratorio, no un incidente real ni un falso positivo.

## Alcance y entorno

- Equipo Windows de laboratorio, con eventos de Security recolectados por Splunk Universal Forwarder.
- Splunk Cloud, índice `main`, sourcetype `XmlWinEventLog:Security`.
- Cuenta temporal creada deshabilitada, agregada al grupo local Administradores solo para validar la detección y eliminada al terminar.
- No se usaron sistemas ni cuentas de producción.

## Detección y telemetría

El evento **4732** indica que se agregó un miembro a un grupo local. En el XML observado:

- `TargetUserName=Administradores` y `TargetSid=S-1-5-32-544` identifican el grupo objetivo.
- `SubjectUserName=genar` identifica el actor registrado en este laboratorio.
- `Computer=Hp` identifica el host.
- `MemberSid` identifica al miembro agregado. En la repetición usada para validar la alerta, el evento no contenía el nombre del miembro (`MemberName=-`); corroboré la cuenta local con `Get-LocalGroupMember`.

En una ejecución preliminar también observé **4720** (creación de `soc_lab_temp_admin`), seguido de **4732**. La limpieza de esa primera cuenta produjo **4733** (remoción del grupo) y **4726** (eliminación de la cuenta). En la prueba final de la alerta usé la cuenta `soc_lab_alert_test` y confirmé su eliminación mediante consultas locales.

## Búsqueda SPL de investigación

La siguiente consulta reconstruye las acciones de creación, alta y limpieza en la ventana de búsqueda:

```spl
index=main earliest=-24h sourcetype=XmlWinEventLog:Security
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=4720 OR EventCode=4732 OR EventCode=4733 OR EventCode=4726
| table _time host EventCode _raw
| sort _time
```

Para revisar específicamente altas en el grupo local Administradores:

```spl
index=main earliest=-15m sourcetype=XmlWinEventLog:Security
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=4732
| rex field=_raw "<Data Name='TargetUserName'>(?<Grupo>[^<]*)</Data>"
| where Grupo="Administradores"
| table _time host EventCode Grupo _raw
| sort - _time
```

## Alerta de Splunk

Configuré la alerta guardada **SOC Lab - Alta en Administradores** con estas condiciones:

- Búsqueda programada cada cinco minutos (`*/5 * * * *`).
- Disparar cuando el número de resultados sea mayor que cero.
- Acción: **Add to Triggered Alerts**.
- Filtro: evento 4732 y grupo objetivo `Administradores`.

Búsqueda configurada:

```spl
index=main earliest=-5m latest=now sourcetype=XmlWinEventLog:Security
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=4732
| rex field=_raw "<Data Name='TargetUserName'>(?<Grupo>[^<]*)</Data>"
| where Grupo="Administradores"
| table _time host EventCode Grupo _raw
```

## Línea de tiempo

Horas UTC del registro de Splunk:

| Hora | Evidencia | Interpretación |
|---|---|---|
| 02:06:30 | Eventos 4720 y 4732 para la primera cuenta temporal | Creación y alta intencional de una cuenta de laboratorio en Administradores. Actor `genar`; host `Hp`. |
| 02:11:24 | Eventos 4733 y 4726 | Remoción de la primera cuenta del grupo y eliminación de la cuenta durante la limpieza. |
| 02:23:31 | Evento 4732 en la validación de alerta | Nueva alta controlada. El SID del miembro se corroboró localmente como `soc_lab_alert_test`. |
| 02:26:45 | Historial de disparos de Splunk | La alerta programada registró una activación luego del evento. |

## Triage L1

1. **Validar la alerta:** confirmé que el evento era 4732 y que el grupo objetivo era Administradores.
2. **Identificar contexto:** revisé host y actor, y resolví el SID del miembro con la lista de usuarios locales y miembros del grupo.
3. **Determinar autorización:** la actividad había sido generada por mí, con una cuenta temporal deshabilitada, dentro del laboratorio.
4. **Clasificar:** verdadero positivo de la detección y cambio autorizado; no se observó actividad maliciosa.
5. **Decidir escalamiento:** en producción, ante un cambio sin ticket, aprobación o ventana de mantenimiento, escalaría a L2 como evento de alta prioridad para validar el actor, el alcance y la legitimidad del acceso.

## Respuesta simulada L2 y verificación

Retiré la cuenta de prueba del grupo local Administradores, eliminé la cuenta y volví a consultar ambos objetos. Las consultas no devolvieron resultados, confirmando que la cuenta ya no existía ni conservaba membresía privilegiada. La limpieza se realizó únicamente sobre la cuenta temporal del laboratorio.

## Mapeo MITRE ATT&CK

- [T1098.007 — Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/): técnica relacionada con agregar cuentas a grupos locales o de dominio para mantener o elevar acceso. Se usa aquí como referencia del comportamiento observado, no como afirmación de actividad adversaria.
- [T1136.001 — Local Account](https://attack.mitre.org/techniques/T1136/001/): relacionada con la creación local de cuenta observada en la ejecución preliminar.

## Resultado y aprendizajes

- Validé la ingesta de Windows Security desde el Universal Forwarder hasta Splunk Cloud.
- Escribí búsquedas SPL para identificar eventos y reconstruir la secuencia.
- Configuré una alerta programada y confirmé su activación desde el historial de Splunk.
- Practiqué triage L1, validación del actor, enriquecimiento de SID, decisión de escalamiento y contención simulada.
- Comprobé que el evento 4732 puede registrar el SID del miembro sin su nombre legible, por lo que hace falta enriquecerlo con datos del endpoint.

## Evidencias

Las capturas están en `img/`. Se conservaron solo las versiones sin duplicados:

1. Resumen de eventos 4720/4732: [01-resumen-eventos-4720-4732.png](img/01-resumen-eventos-4720-4732.png)
2. Detalle XML del 4732, actor y grupo: [02-detalle-evento-4732.png](img/02-detalle-evento-4732.png)
3. Eventos de limpieza 4733/4726: [03-eventos-limpieza-4733-4726.png](img/03-eventos-limpieza-4733-4726.png)
4. Alerta programada cada cinco minutos: [04-alerta-programada-cada-5-min.png](img/04-alerta-programada-cada-5-min.png)
5. Historial con el disparo a las 02:26:45 UTC: [05-historial-disparo-alerta.png](img/05-historial-disparo-alerta.png)
6. Búsqueda del evento 4732 de la validación: [06-busqueda-evento-prueba-4732.png](img/06-busqueda-evento-prueba-4732.png)

> **Privacidad:** las capturas muestran el usuario local, el nombre del equipo y SID locales. Antes de publicar el repositorio como público, ocultá esos datos si preferís no asociarlos a tu perfil. Conservá visibles el Event ID, el grupo, las horas y el historial de la alerta.

---

**Nota:** este caso documenta una simulación educativa en un equipo propio. No representa una investigación de un incidente en una organización real.
