# Caso 004 — Alta de miembro en Administradores locales con Splunk

**Tipo:** Gestión de cuentas / Escalada de privilegios potencial  
**Severidad de referencia:** Alta si el cambio no está autorizado  
**Entorno:** Laboratorio propio con Windows, Splunk Universal Forwarder y Splunk Cloud  
**Estado:** Ejercicio controlado; actividad autorizada y benigna

## Resumen

Se creó una cuenta local temporal deshabilitada y se la agregó al grupo local **Administradores** para validar la telemetría y el flujo de trabajo de una alerta SOC. El evento de Windows **4732** fue recolectado por el Universal Forwarder, consultado con SPL y detectado por una alerta programada de Splunk. Se revisó el actor, el host, el grupo y el SID del miembro. Luego se quitó la cuenta del grupo y se eliminó; la verificación local confirmó que ya no estaba presente.

La actividad fue generada intencionalmente por el operador del laboratorio. Por eso, el cambio detectado fue **verdadero positivo de la regla y actividad benigna autorizada**; no fue un incidente real ni un falso positivo.

## Objetivo de detección

Detectar la incorporación de una cuenta a un grupo local privilegiado, identificar quién realizó el cambio y en qué equipo, y escalar a L2 si no existe una autorización válida.

## Fuentes y eventos

- **Fuente:** Windows Security Event Log, recolectado por Splunk Universal Forwarder.
- **Índice y sourcetype:** `main`, `XmlWinEventLog:Security`.
- **4720:** creación de una cuenta local. En la primera ejecución del escenario se observó la creación de `soc_lab_temp_admin` por `genar` en `Hp`.
- **4732:** incorporación de un miembro a un grupo local. Se observó `TargetUserName=Administradores`, `TargetSid=S-1-5-32-544`, host `Hp` y actor `genar`.
- **4733 y 4726:** eventos de remoción de miembro y eliminación de cuenta observados durante la limpieza de la primera cuenta temporal.

En la prueba de funcionamiento de la alerta se usó una segunda cuenta, `soc_lab_alert_test`, creada deshabilitada. El evento 4732 mostró el SID del miembro terminado en `-1007`; el nombre de la cuenta se corroboró localmente con `Get-LocalGroupMember`. El XML de este evento no incluía el nombre del miembro (`MemberName` aparecía como `-`), por lo que el SID debía enriquecerse con la información local del equipo.

## Búsqueda SPL de investigación

```spl
index=main earliest=-24h sourcetype=XmlWinEventLog:Security
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=4720 OR EventCode=4732 OR EventCode=4733 OR EventCode=4726
| table _time host EventCode _raw
| sort _time
```

La búsqueda extrae `EventCode` del XML crudo y muestra la secuencia temporal para revisar creación, alta en el grupo y acciones de limpieza.

## Regla de alerta

Se configuró la alerta guardada **SOC Lab - Alta en Administradores**:

- Búsqueda programada cada cinco minutos (`*/5 * * * *`).
- Disparo cuando los resultados son mayores que cero.
- Acción: **Add to Triggered Alerts**.
- La búsqueda filtra el evento 4732 y el grupo local `Administradores`.

Consulta usada por la alerta:

```spl
index=main earliest=-5m latest=now sourcetype=XmlWinEventLog:Security
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=4732
| rex field=_raw "<Data Name='TargetUserName'>(?<Grupo>[^<]*)</Data>"
| where Grupo="Administradores"
| table _time host EventCode Grupo _raw
```

## Línea de tiempo observada (UTC)

| Hora | Evidencia | Interpretación |
|---|---|---|
| 02:06:30 | 4720 para `soc_lab_temp_admin`; actor `genar`, host `Hp` | Creación de la cuenta temporal en la primera ejecución del escenario. |
| 02:06:30 | 4732; el grupo objetivo es `Administradores` (SID `S-1-5-32-544`) | Incorporación de la cuenta al grupo local privilegiado. |
| 02:11:24 | 4733 y 4726 para la primera cuenta temporal | Remoción del grupo y eliminación durante la limpieza del laboratorio. |
| 02:23:31 | 4732; actor `genar`, host `Hp`, SID de miembro terminado en `-1007` | Repetición controlada para validar el disparo de la alerta. La pertenencia se corroboró localmente para `soc_lab_alert_test`. |
| 02:26:45 | Historial de disparos de Splunk | La alerta programada registró una activación tras la prueba. |

## Análisis y triage L1

1. **Validación de la señal:** el evento 4732 confirma un cambio real de membresía; el grupo objetivo es el grupo local de Administradores.
2. **Contexto:** el host y el actor corresponden al equipo y al operador del laboratorio. La cuenta se creó deliberadamente para la práctica y se mantuvo deshabilitada.
3. **Enriquecimiento:** el evento mostró el SID del miembro, no su nombre. Se verificó la cuenta en el grupo local antes de retirarla.
4. **Clasificación:** verdadero positivo de la regla, pero actividad benigna y autorizada dentro del laboratorio. No se clasifica como incidente malicioso.
5. **Escalamiento:** en un entorno productivo, si el cambio no estuviera asociado a un ticket, administrador autorizado o ventana de mantenimiento, correspondería escalar a L2 con prioridad alta para validar alcance y autorización.

## Respuesta simulada (L2)

- Retirar la cuenta temporal del grupo local Administradores.
- Eliminar la cuenta de prueba.
- Verificar que `Get-LocalGroupMember -SID "S-1-5-32-544"` ya no la devuelve y que `Get-LocalUser` no encuentra la cuenta.
- Conservar los eventos de detección, el historial de disparo de la alerta y la evidencia de validación y limpieza.

La limpieza fue simulada y se ejecutó únicamente sobre las cuentas temporales creadas para este ejercicio. No se realizó una respuesta sobre un sistema de producción.

## Mapeo MITRE ATT&CK

- **T1098.007 — Additional Local or Domain Groups:** agregar una cuenta a un grupo local puede otorgarle privilegios adicionales.
- **T1136.001 — Create Local Account:** aplica a la etapa de creación de la cuenta local observada en la primera ejecución.

El mapeo describe técnicas asociadas al comportamiento; por sí solo no indica que la actividad del laboratorio fuera maliciosa.

## Resultado y aprendizajes

- Confirmé la recolección de Windows Security en Splunk Cloud a través del Universal Forwarder.
- Escribí y ejecuté búsquedas SPL para reconstruir la secuencia de eventos.
- Configuré una alerta programada de cinco minutos y confirmé una activación en su historial.
- Practiqué triage L1, enriquecimiento de SID, criterio de escalamiento y una contención simulada.
- Aprendí que el evento 4732 identifica el grupo objetivo, pero el nombre del miembro puede requerir enriquecimiento adicional.

## Evidencias sugeridas

Agregar al repositorio capturas recortadas de: (1) resultados 4720/4732, (2) evento 4732 con actor, grupo y SID, (3) 4733/4726 de la limpieza inicial, (4) configuración de la alerta cada cinco minutos y (5) historial de disparo a las 02:26:45 UTC. No publicar credenciales, paquetes `.spl`, SID completos, URL privada del tenant ni datos personales innecesarios. Las capturas duplicadas pueden omitirse.

> **Alcance:** práctica educativa en laboratorio propio. Los nombres y detalles del entorno deben anonimizarse antes de publicar capturas.
