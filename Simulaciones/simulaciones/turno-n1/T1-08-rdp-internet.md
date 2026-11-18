# T1-08 · Sesión de escritorio remoto desde Internet a un servidor

**Veredicto:** Verdadero positivo · **Acción:** Contener y escalar · **MITRE:** T1021.001 (Remote Services: Remote Desktop Protocol)

## Alerta
Conexión RDP desde una IP externa hacia un servidor SQL.

## Evidencia clave
```text
13:22:40 win-SRV-SQL01 EventID=4625 TargetUserName=administrador IpAddress=203.0.113.80 LogonType=10
13:23:02 win-SRV-SQL01 EventID=4624 TargetUserName=administrador IpAddress=203.0.113.80 LogonType=10
```

## Análisis
- Desde la IP externa `203.0.113.80` hay un intento de autenticación fallido (4625) seguido de uno exitoso (4624) con la cuenta privilegiada `administrador`, en menos de un minuto.
- La conexión entró por la regla de firewall TEMP-PROVEEDOR, que no tiene fecha de caducidad.
- Después del acceso se ejecutó `C:\Users\Public\ad.exe`, un ejecutable en una carpeta pública, lo que es sospechoso.
- Un RDP desde Internet a un servidor interno con una cuenta de administrador, más un ejecutable desconocido, apunta a un posible compromiso.

## Decisión
Verdadero positivo sospechoso. Se solicita contención inmediata, preservación de evidencias e investigación de N2 para determinar el alcance.

## Siguientes pasos sugeridos para N2
1. Aislar el servidor y cerrar o restringir la regla TEMP-PROVEEDOR.
2. Analizar `ad.exe` y buscar persistencia o movimiento lateral desde SRV-SQL01.
3. Restablecer las credenciales de la cuenta `administrador`.
