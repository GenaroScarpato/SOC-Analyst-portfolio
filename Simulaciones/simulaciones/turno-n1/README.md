# Simulación de turno SOC N1

Turno de triaje en una empresa ficticia, con alertas y registros simulados. Es un ejercicio formativo con corrección automática: los análisis, veredictos y textos son míos; los escenarios y registros pertenecen al simulador ([Blue-Jr](https://github.com/heindall92/Blue-Jr)).

**Resultado del turno:** 8 alertas analizadas, 100 % de veredictos correctos y 0 amenazas cerradas por error.

## Casos destacados

| Caso | Alerta | Veredicto | Acción | MITRE |
|---|---|---|---|---|
| [T1-04](T1-04-admin-local-finanzas.md) | Administrador local creado en un equipo de Finanzas | Verdadero positivo | Contener y escalar | T1136.001 |
| [T1-07](T1-07-usb-nominas.md) | Más de 1 GB de nóminas copiado a un USB | Verdadero positivo | Escalar a N2 | T1052.001 |
| [T1-08](T1-08-rdp-internet.md) | RDP desde Internet a un servidor SQL | Verdadero positivo | Contener y escalar | T1021.001 |
| [T1-05](T1-05-viaje-imposible-vpn.md) | Inicios de sesión desde Madrid y Fráncfort en 10 minutos | Falso positivo | Cerrar | — |

Además: [informe de relevo del T1-07](informe-relevo-T1-07.md), con el estado del caso y los pasos pendientes para N2.

## Qué muestran estos casos

- **Criterio para escalar:** tres verdaderos positivos con la evidencia que justifica cada decisión.
- **Criterio para no escalar:** un falso positivo explicado por correlación de fuentes (VPN corporativa, MFA y dispositivo conforme).
- **Documentación:** un relevo escrito para que N2 continúe sin repetir el trabajo.

Los otros cuatro casos del turno (fuerza bruta en VPN, escaneo de puertos, prueba de antivirus y sesión RDP de mantenimiento) no se incluyen aquí.
