# Diagnóstico: bloqueo de TCP/25 saliente en `server1` (check STARTTLS de MEDICIONES)

**Fecha:** 2026-09-17 · **Alcance:** diagnóstico de infraestructura únicamente. No se modificó código, firewall, reglas del proveedor, ni se instaló nada. No se envió correo, no se autenticó, no se intentó relay, no se escaneó ningún rango de puertos.

---

## 1. Entorno identificado

| Dato | Valor |
|---|---|
| Hostname | `server1` |
| SO | Ubuntu 26.04 LTS ("Resolute Raccoon"), kernel 7.0.0-28-generic |
| Uptime | 49 días (proceso estable, no reiniciado recientemente) |
| Runtime de MEDICIONES | **Docker** — contenedor `mediciones`, imagen `mediciones-mediciones`, red `mediciones_default` (bridge dedicado, no `host` networking) |
| Publicación de puertos | `0.0.0.0:8700->8700/tcp` (y `[::]:8700`) — solo el puerto de la app, nada relacionado a SMTP |
| Interfaz física | `enp2s0`, IP `192.168.100.3/26`, gateway `192.168.100.1` vía DHCP — **LAN privada detrás de un router**, no una IP pública asignada directo a la máquina |
| Red mesh | Tailscale activo (`tailscale0`, `100.74.149.70`) — es como se accede a esta máquina en esta sesión, sin relación con el problema de puerto 25 |
| `docker-compose.yml` | Servicio simple: `build .`, `ports: 8700:8700`, `env_file: .env`, volumen `./data:/app/data` — **sin configuración de red especial, sin restricciones de egress definidas a nivel de Docker Compose** |
| Firewall local (ufw/iptables/nft) | **NO DETERMINABLE** con el acceso disponible — `/etc/ufw/` existe (el paquete está instalado) pero sus archivos son `root:root 640` (no legibles sin root), y `sudo` en esta sesión no interactiva requiere contraseña (`sudo: interactive authentication is required`) para `ufw status`, `iptables -L` y `nft list ruleset` por igual. No se intentó ni se intentará obtener esa contraseña. |

No se mostraron secretos, tokens ni credenciales en ningún paso.

## 2. Pruebas de conectividad TCP realizadas (mínimas, sin enviar datos)

Herramienta usada: `timeout N bash -c 'exec 3<>/dev/tcp/IP/PUERTO'` — abre y cierra un socket TCP crudo, sin escribir ni leer ningún byte (no hay handshake SMTP, no hay EHLO, no hay STARTTLS, no hay autenticación). Se resolvieron los hostnames a IP primero (por separado, solo DNS) para no mezclar fallo DNS con fallo TCP.

| # | Destino | IP resuelta | Puerto | Resultado | Tiempo | Clasificación |
|---|---|---|---|---|---|---|
| 1 | `gmail-smtp-in.l.google.com` (MX de gmail.com, prioridad 5) | `172.253.147.27` (pública, AS de Google) | 25 | Sin respuesta — `timeout` mató el proceso | 8042 ms (el timeout completo) | **TIMEOUT** |
| 2 | `outlook-com.olc.protection.outlook.com` (MX de outlook.com, prioridad 5) | `52.101.73.122` (pública, AS de Microsoft) | 25 | Sin respuesta — `timeout` mató el proceso | 8018 ms (el timeout completo) | **TIMEOUT** |
| 3 (control) | `www.google.com` | — (resuelta internamente) | 443 | Conecta | 108 ms | Éxito — descarta problema de red/DNS general |

Las IPs resueltas para los MX (`172.253.147.27`, `52.101.73.122`) son direcciones **públicas** de Google y Microsoft respectivamente — no son privadas, loopback ni reservadas. No hubo confusión posible entre fallo DNS y fallo TCP: la resolución de nombres funcionó correctamente en los tres casos (se obtuvo una IP válida antes de cada intento de conexión).

## 3. Host vs. contenedor

Se repitieron las mismas pruebas (Gmail/25 y Google/443) **desde dentro del contenedor** `mediciones` vía `docker exec` (bash ya está presente en la imagen, no se instaló nada):

| Prueba | Host | Contenedor |
|---|---|---|
| TCP/25 → Gmail (`172.253.147.27`) | timeout, 8042 ms | timeout, 8007 ms |
| TCP/443 → `www.google.com` (control) | éxito, 108 ms | éxito, 35 ms |

**Host falla / contenedor falla — idéntico en ambos.** Según el criterio de interpretación de esta tarea, esto apunta a un **bloqueo externo al contenedor** (a nivel del host, de la red local, o más arriba) — no es un problema del runtime de Docker ni de la red interna del contenedor (`mediciones_default`), porque el mismo patrón se repite exactamente igual fuera de él.

## 4. Firewall local — resultado de la revisión

**NO DETERMINABLE.** Se intentó (sin `sudo -n` con contraseña, sin modificar nada):
- `ufw status verbose` → requiere autenticación interactiva.
- `iptables -L OUTPUT -n` (sin sudo) → `Permission denied (you must be root)`.
- `nft list ruleset` (sin sudo) → requiere autenticación interactiva.
- Lectura directa de `/etc/ufw/*.rules` → permisos `640 root:root`, no legibles con el usuario de esta sesión.

No se encontró evidencia de una regla de bloqueo explícita, pero tampoco se pudo descartar su existencia — la ausencia de evidencia no es evidencia de ausencia en este punto específico. Esto se señala honestamente en vez de asumir.

## 5. DNS y ruta

- `gmail-smtp-in.l.google.com` → `172.253.147.27` (pública).
- `outlook-com.olc.protection.outlook.com` → `52.101.73.122` / `52.101.91.20` / `52.101.10.3` (públicas, rango de Microsoft/Azure).
- Ninguna de las IPs resueltas es privada (RFC1918), loopback ni reservada — se descarta que el "bloqueo" sea en realidad un error de resolución hacia una dirección inválida.
- No se ejecutó traceroute (invasivo/fuera del alcance pedido); la ruta normal no se pudo inspeccionar hop a hop, pero no hace falta para la conclusión: un fallo de ruteo genérico (`NETWORK UNREACHABLE`) habría dado un error inmediato de "No route to host", no un timeout silencioso de 8 segundos completos.

## 6. Clasificación del fallo

- ❌ **CONNECTION REFUSED** — no ocurrió; un rechazo activo devuelve el error casi de inmediato (el destino responde con RST). Acá no hubo respuesta alguna.
- ✅ **TIMEOUT** — confirmado en las 4 pruebas de puerto 25 (2 destinos × host/contenedor): el SYN saliente no recibe respuesta, consistente con que algo en el camino **descarta silenciosamente** los paquetes (no los rechaza activamente).
- ❌ **NETWORK UNREACHABLE** — descartado: el control de puerto 443 hacia la misma familia de infraestructura (Google) conecta en ~100ms, y la resolución DNS de los tres destinos fue exitosa.
- **LOCAL POLICY BLOCK** — NO DETERMINABLE (ver §4): no se pudo confirmar ni descartar por falta de acceso root al firewall del host.
- ✅ **PROVIDER/UPSTREAM BLOCK LIKELY** — es la clasificación con más evidencia a favor: no hay bloqueo local *visible* (aunque tampoco se pudo verificar con certeza), múltiples MX públicos independientes y confiables (Google, Microsoft) dan timeout uniforme en el puerto 25, mientras que el 443 funciona correctamente contra la misma infraestructura — exactamente el patrón que esta tarea define como indicador de esta categoría.

## 7. Proveedor identificado

Se consultó (lectura pública, sin credenciales, sin cambiar nada) la IP pública de salida real de `server1`:

```
IP pública de salida: 186.178.66.109
Hostname reverso:     109.66.178.186.static.anycast.cnt-grms.ec
Organización (WHOIS):  AS28006 CORPORACION NACIONAL DE TELECOMUNICACIONES - CNT EP
Ubicación:             Manta, Manabí, Ecuador
```

**Proveedor identificado con certeza: CNT EP** (Corporación Nacional de Telecomunicaciones, el operador estatal de telecomunicaciones de Ecuador) — **no** un proveedor de hosting/VPS/nube. El nombre reverso (`static.anycast.cnt-grms.ec`) indica una IP fija de un enlace de banda ancha fijo (hogar/oficina), consistente con lo ya documentado del proyecto ("home-lab").

**¿CNT bloquea SMTP/25 por política?** No se encontró ni se buscó documentación oficial de CNT sobre esto desde este acceso (no corresponde a esta tarea abrir tickets ni consultar al proveedor) — pero el bloqueo/filtrado de puerto 25 saliente en conexiones residenciales/de banda ancha fija es una práctica **extremadamente común entre operadores de telecomunicaciones en general** (no exclusiva de CNT) para contener spam desde equipos comprometidos de clientes. La combinación de (a) el patrón de fallo observado (timeout silencioso, no rechazo activo), (b) idéntico en host y contenedor, y (c) el hecho de que el enlace es residencial/banda-ancha-fija de un operador nacional y no un datacenter, hace de esta la explicación **más probable**, aunque no se pudo confirmar contra una política documentada públicamente de CNT desde este diagnóstico.

## 8. Comparación de opciones

### Opción A — Habilitar TCP/25 saliente en `server1`
- **Complejidad**: alta y fuera de nuestro control directo — depende de que CNT lo permita para este tipo de conexión (residencial/banda ancha fija), lo cual no está garantizado y probablemente requiera una gestión comercial con el proveedor (cambio de plan, solicitud explícita, o puede que simplemente no esté disponible para este tipo de servicio).
- **Seguridad**: neutra en sí misma (no abre nada nuevo hacia adentro, es tráfico saliente).
- **Intervención del proveedor**: **sí, imprescindible** — sin acción de CNT, no hay nada que MEDICIONES o el propio servidor puedan hacer para revertir un bloqueo a nivel de red del ISP.
- **Cambio local**: ninguno, si el proveedor lo habilita.

### Opción B — Worker/nodo externo solo para STARTTLS
- **Complejidad**: la más alta de las tres — requiere aprovisionar y mantener una máquina/servicio externo, exponer un mecanismo para que MEDICIONES le delegue la sonda STARTTLS, y manejar su ciclo de vida (parches, disponibilidad, costo).
- **Seguridad**: agrega superficie nueva — un componente adicional con salida a puerto 25 hacia internet es, en sí mismo, el tipo de recurso que requiere cuidado (podría ser mal utilizado si se compromete). Además, muchos proveedores de nube (AWS, GCP, Azure, DigitalOcean) **también bloquean el puerto 25 saliente por defecto** en cuentas nuevas y requieren una solicitud de desbloqueo — no hay garantía de que resuelva el problema más rápido que la Opción A.
- **Costo/mantenimiento**: recurrente (una máquina o servicio más que mantener, actualizar y monitorear, para un único check de baja frecuencia de uso).

### Opción C — Deshabilitar temporalmente STARTTLS en producción, código listo
- **Impacto funcional**: mínimo. El check `starttls` ya nace con `default:false` en `groupDefinitions` (no se ejecuta salvo que alguien lo seleccione explícitamente), y cuando corre bajo este bloqueo ya devuelve `MEASUREMENT_ERROR`/`INCONCLUSIVE` por timeout de forma honesta — **no miente, no se cuelga, no rompe el resto de la corrida**. Deshabilitarlo del todo solo evita que alguien lo seleccione y reciba siempre el mismo resultado no informativo.
- **Simplicidad**: la más alta — es, en el límite, ni siquiera necesario tocar código (ya se comporta de forma segura); como mucho, ocultar el checkbox o agregar una nota visible de "temporalmente no disponible por restricción de red del servidor".
- **Reversibilidad**: total e inmediata — no depende de nadie más que de nosotros, y no hay que deshacer ninguna configuración de infraestructura.

## 9. Recomendación

Según el criterio pedido (seguridad → simplicidad → mínimo cambio → mínima dependencia adicional → reversibilidad):

**Recomendación inmediata: Opción C**, con una precisión importante: como el check ya está diseñado para fallar de forma segura y honesta (`INCONCLUSIVE`, no `FAIL`, no cuelgue) y ya no viene preseleccionado por defecto, el "cambio" mínimo necesario no es de código — es, como mucho, documentar visiblemente esta limitación (por ejemplo, en el tooltip/glosario del check) para que quien lo seleccione entienda por qué siempre da timeout en este servidor, sin necesidad de ocultar ni remover nada.

**Recomendación de seguimiento, no urgente: Opción A** — vale la pena, en algún momento, consultar directamente con CNT si el plan/servicio contratado admite habilitar el egress de puerto 25 (ej. subiendo a un plan de negocio, o una solicitud puntual) — es arquitectónicamente la solución más simple SI el proveedor lo permite, porque no agrega ningún componente nuevo al sistema.

**No se recomienda la Opción B** como primer recurso: agrega complejidad y una superficie de mantenimiento permanente para resolver la limitación de un solo check de baja prioridad, con un beneficio incierto (los proveedores de nube suelen tener la misma restricción por defecto).

No se evaluó el puerto 587 como sustituto de 25, según lo solicitado explícitamente — no resuelve la pregunta funcional de STARTTLS entre servidores de correo (ver `IMPLEMENTACION_MEDICIONES_FASE1_CORREO.md` §11).

---

*Ninguna configuración fue modificada durante este diagnóstico. Todas las pruebas fueron conexiones TCP puras, sin datos SMTP, sin autenticación, sin relay, sin escaneo de puertos ni rangos.*
