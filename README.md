# Honeypot SSH con Cowrie — Análisis de Inteligencia de Amenazas

Proyecto Intermodular · ASIR · Curso 2025–2026
**Alumno:** Diego Pérez Fonterosa
**Centro:** Prometeo FP (thePower Education)

## Descripción

Despliegue de un honeypot SSH expuesto a Internet utilizando [Cowrie](https://github.com/cowrie/cowrie), un software libre de media interacción que simula un servidor Linux vulnerable. El sistema captura ataques reales (fuerza bruta, comandos ejecutados, descargas de malware) y genera un informe de inteligencia de amenazas con mapeo [MITRE ATT&CK](https://attack.mitre.org/).

## Resultados principales

Honeypot en producción desde el **4 de octubre de 2026**. Periodo de captura: un mes (hasta el 1 de noviembre de 2026).

| Indicador | Valor |
|---|---|
| Conexiones en las primeras 72 horas | 13.761 |
| IP únicas en las primeras 72 horas | 499 |
| Mayor campaña detectada (10–11 oct.) | 21.919 sesiones desde 38 IP con la misma huella HASSH |
| Contraseñas distintas probadas contra `root` en esa campaña | 9.919 |
| Casos de prueba del clasificador MITRE ATT&CK | 50 |

### Campañas identificadas

- **Outlaw/Dota:** botnet identificada por la clave SSH con la firma `mdrfckr` que inserta en `authorized_keys` para mantener el acceso. Llegó a 441 IP distintas en los primeros 13 días.
- **RedTail:** criptominero que sube binarios para varias arquitecturas por SFTP.
- **Campaña de verificación de credenciales (10–11 oct.):** una sola herramienta, identificada por su huella HASSH, repartida entre 38 IP.
- **Verificador `echo xsec`:** campaña más pequeña que comprueba si el acceso es válido antes de continuar.

> Las cifras son preliminares y corresponden a las primeras semanas. La tabla de técnicas MITRE ATT&CK, las gráficas y el análisis de los 28 días completos se publicarán al cerrar el periodo de captura (noviembre de 2026).

## Estado del proyecto

| Componente | Estado |
|---|---|
| Servidor cloud, hardening y firewall | Operativo |
| Cowrie 3.1.0 bajo systemd (puerto 22 → 2222) | Operativo desde el 4 de octubre |
| Analizador en Python y clasificador MITRE (50 pruebas) | Terminado |
| Pruebas funcionales (escaneo con nmap y ataque controlado desde Kali) | Realizadas |
| Análisis final de 28 días e informe de inteligencia | En curso |
| Integración con Wazuh | Instalado; ingesta de los logs de Cowrie prevista |

Los logs reales y las IP de los atacantes no se publican en este repositorio.

## Arquitectura

- **Servidor cloud:** Hetzner Cloud CX23 (Ubuntu Server 24.04, 2 vCPU, 4 GB RAM, Núremberg, IPv4 pública)
- **Firewall:** Hetzner Cloud Firewall (entrada: TCP 22 abierto, TCP 2022 solo desde la IP del administrador e ICMP) + iptables en el servidor
- **Honeypot:** Cowrie escuchando en el puerto 22 (redirección NAT 22 → 2222 con iptables)
- **SSH de administración:** puerto 2022, restringido a la IP del administrador, acceso exclusivo por clave y sin root
- **Laboratorio local:** VirtualBox con Wazuh 4.9.2 (SIEM, instalado; ingesta de logs prevista) y Kali Linux (ataque controlado)

El anteproyecto preveía Oracle Cloud Always Free; se cambió a Hetzner por falta de capacidad en la región de Oracle. Los scripts de `config/` son válidos para ambos proveedores.

## Estructura del repositorio

```
PFC-Cowrie/
├── docs/              # Anteproyecto y memoria del proyecto
├── scripts/           # Scripts Python de análisis y generación de datos
├── config/            # Scripts de despliegue y configuración (Cowrie, SSH, iptables, systemd)
├── logs/
│   └── sample/        # Logs de ejemplo para pruebas
├── capturas/          # Capturas de pantalla organizadas por fase
│   ├── fase1-despliegue/
│   ├── fase2-hardening/
│   ├── fase3-cowrie/
│   ├── fase4-captura/
│   ├── fase5-analisis/
│   └── fase6-informe/
└── graficas/          # Gráficas generadas por el script de análisis
```

## Uso del script de análisis

```bash
# Generar datos de ejemplo para pruebas
python3 scripts/generate_sample_logs.py

# Analizar logs (con geolocalización)
python3 scripts/cowrie_analyzer.py cowrie.json --output graficas/

# Analizar logs (sin conexión a Internet)
python3 scripts/cowrie_analyzer.py cowrie.json --output graficas/ --no-geo

# Excluir las sesiones de prueba propias (localhost se excluye siempre)
python3 scripts/cowrie_analyzer.py cowrie.json --output graficas/ --exclude-ip <TU_IP_PUBLICA>

# Pruebas del clasificador MITRE ATT&CK
python3 scripts/test_mitre_mapping.py
```

El script genera:

- Ranking de IPs atacantes con geolocalización
- Credenciales más probadas (usuario y contraseña)
- Comandos más ejecutados tras el acceso
- Ficheros/malware descargados y URLs de descarga en los comandos (IOC)
- Agrupación de sesiones por huella HASSH del cliente SSH
- Clasificación de la actividad en técnicas MITRE ATT&CK con evidencias y recomendaciones (`mitre_mapping.py`), también exportada a `mitre_mapping.csv`
- Gráficas en PNG y un informe de resumen en texto

## Herramientas

- **Cowrie** — honeypot SSH/Telnet de media interacción
- **Python 3** — análisis de logs (json, collections, matplotlib)
- **Wazuh 4.9.2** — SIEM para ingesta y visualización (opcional; instalado, ingesta de logs prevista)
- **MITRE ATT&CK** — marco de referencia para clasificación de actividad
- **ip-api.com / GeoLite2** — geolocalización de IPs atacantes

## Más información

Análisis de las primeras 72 horas en el blog: [72 horas con un honeypot SSH: quién ataca y qué hace](https://lapaginadedraven.atwebpages.com/)

## Licencia

Proyecto académico. El código de los scripts es de uso libre.
