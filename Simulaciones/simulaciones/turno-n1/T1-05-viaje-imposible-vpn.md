# T1-05 · Inicios de sesión desde Madrid y Fráncfort en 10 minutos

**Veredicto:** Falso positivo · **Acción:** Cerrar

## Alerta
Alerta de viaje imposible para `j.romero`: un inicio de sesión desde Madrid y otro desde Fráncfort con 10 minutos de diferencia.

## Evidencia clave
```text
10:02:11 entra SignIn result=success user=j.romero app=Outlook ip=192.0.2.1 geo=Madrid,ES mfa=satisfied
10:11:40 vpnprov j.romero conectado a la VPN corporativa · nodo de salida FRA-02 · egress=198.51.100.77
10:12:05 entra SignIn result=success user=j.romero app=Teams ip=198.51.100.77 geo=Frankfurt,DE mfa=satisfied device=PC-MKT-002 compliant=true
10:12:06 entra note: 198.51.100.77 pertenece al rango de salida del proveedor VPN corporativo
```

## Análisis
- El segundo inicio de sesión usó la IP `198.51.100.77`, que corresponde al nodo de salida FRA-02 de la VPN corporativa.
- El registro del proveedor VPN muestra la conexión del usuario 25 segundos antes de ese inicio de sesión.
- El acceso tuvo MFA satisfecho y desde un dispositivo conforme (`compliant=true`).
- La diferencia geográfica se explica por el nodo de salida de la VPN, no por un desplazamiento real.

## Decisión
Falso positivo. Se cierra sin escalar.

## Lección
Una alerta de viaje imposible se descarta con evidencia cruzada de tres fuentes: el proveedor VPN, la identidad del dispositivo y el MFA. Con una sola fuente no habría bastado.
