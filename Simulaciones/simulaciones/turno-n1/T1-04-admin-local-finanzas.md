# T1-04 · Administrador local creado en un equipo de Finanzas

**Veredicto:** Verdadero positivo · **Acción:** Contener y escalar · **MITRE:** T1136.001 (Create Account: Local Account)

## Alerta
Se crea una cuenta local con privilegios de administrador en un equipo del área de Finanzas.

## Evidencia clave
```text
09:37:51 win-PC-FIN-007 EventID=4688 NewProcessName=C:\Windows\System32\net.exe CommandLine='net user soporte$ ******** /add' SubjectUserName=p.sanz ParentProcessName=cmd.exe
09:37:51 win-PC-FIN-007 EventID=4720 TargetUserName=soporte$ SubjectUserName=p.sanz
09:37:58 win-PC-FIN-007 EventID=4688 CommandLine='net localgroup administradores soporte$ /add' SubjectUserName=p.sanz
09:37:58 win-PC-FIN-007 EventID=4732 MemberName=soporte$ TargetUserName=Administradores SubjectUserName=p.sanz
```
(Contraseña ocultada en este extracto.)

## Análisis
- Los eventos 4720 y 4732 confirman la creación de la cuenta `soporte$` y su alta en el grupo local Administradores.
- Los eventos 4688 muestran que ambos cambios se hicieron con `net.exe` desde `cmd.exe`, con el usuario `p.sanz`.
- La consulta a ITSM no encontró ningún cambio autorizado para el equipo.
- El nombre termina en `$`, algo habitual para que una cuenta pase por cuenta de equipo.

## Decisión
Verdadero positivo de alta prioridad. Se solicita contención del equipo, se escala a N2 y se pide validar la actividad de `p.sanz` por un posible compromiso de privilegios.

## Siguientes pasos sugeridos para N2
1. Confirmar con `p.sanz` si realizó la acción y revisar si su cuenta está comprometida.
2. Deshabilitar `soporte$` y buscar usos posteriores de esa cuenta.
3. Revisar otros equipos por altas similares en el grupo Administradores.
