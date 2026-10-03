# Honeypot SSH con Cowrie — Análisis de Inteligencia de Amenazas

Proyecto Intermodular · ASIR · Curso 2025–2026  
**Alumno:** Diego Pérez Fonterosa  
**Centro:** Prometeo FP (thePower Education)

## Descripción

Despliegue de un honeypot SSH expuesto a Internet utilizando [Cowrie](https://github.com/cowrie/cowrie), un software libre de media interacción que simula un servidor Linux vulnerable. El sistema captura ataques reales (fuerza bruta, comandos ejecutados, descargas de malware) y genera un informe de inteligencia de amenazas con mapeo [MITRE ATT&CK](https://attack.mitre.org/).

## Arquitectura

- **Servidor cloud:** Oracle Cloud Always Free (Ubuntu Server, IP pública)
- **Honeypot:** Cowrie escuchando en el puerto 22 (redirigido desde iptables)
- **SSH de administración:** puerto 2022, acceso exclusivo por clave
- **Laboratorio local:** VirtualBox con Wazuh 4.9.2 (SIEM) y Kali Linux (ataque controlado)

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

# Pruebas del clasificador MITRE ATT&CK
python3 scripts/test_mitre_mapping.py
```

El script genera:
- Ranking de IPs atacantes con geolocalización
- Credenciales más probadas (usuario y contraseña)
- Comandos más ejecutados tras el acceso
- Ficheros/malware descargados y URLs de descarga en los comandos (IOC)
- Clasificación de la actividad en técnicas MITRE ATT&CK con evidencias y recomendaciones (`mitre_mapping.py`), también exportada a `mitre_mapping.csv`
- Gráficas en PNG y un informe de resumen en texto

## Herramientas

- **Cowrie** — honeypot SSH/Telnet de media interacción
- **Python 3** — análisis de logs (json, collections, matplotlib)
- **Wazuh 4.9.2** — SIEM para ingesta y visualización (opcional)
- **MITRE ATT&CK** — marco de referencia para clasificación de actividad
- **ip-api.com / GeoLite2** — geolocalización de IPs atacantes

## Licencia

Proyecto académico. El código de los scripts es de uso libre.
