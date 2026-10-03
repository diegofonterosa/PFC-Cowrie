# Despliegue del honeypot

Ficheros para pasar de un Ubuntu Server 24.04 recién creado a un honeypot Cowrie expuesto en el puerto 22. Se ejecutan en orden y cada script comprueba que el anterior se completó.

| Paso | Fichero | Qué hace |
|---|---|---|
| 0 | (consola OCI) | Abrir 2022/TCP en la Security List de la subnet |
| 1 | `01_hardening.sh` | Actualizaciones, swap si hace falta, firewall iptables, SSH real al 2022 solo con clave |
| — | (otra terminal) | Comprobar `ssh -p 2022 ubuntu@IP` antes de seguir |
| 2 | `02_instalar_cowrie.sh` | Usuario `cowrie`, Cowrie 3.1.0 en venv, configuración y servicio systemd |
| 3 | `03_redireccion_22.sh` | Redirección NAT 22 → 2222: el honeypot pasa a ser público |

```bash
scp -P 22 -r config/ ubuntu@IP:~/      # aún por el 22, antes del paso 1
ssh ubuntu@IP
cd config && sudo bash 01_hardening.sh
```

## Ficheros de configuración

- `cowrie.cfg`: solo las claves que cambian respecto a los valores por defecto (nombre de host, identidad Debian 12, log JSON único, Telnet desactivado).
- `userdb.txt`: credenciales aceptadas. **Debe ser ASCII puro**: con una tilde, Cowrie rechaza todos los logins sin dar error.
- `sshd_hardening.conf`: SSH de administración (puerto 2022, solo clave, sin root).
- `cowrie.service`: unidad de systemd con el servicio confinado (solo puede escribir en `var/`).

## Comandos útiles

```bash
sudo systemctl status cowrie                 # estado del honeypot
sudo journalctl -u cowrie -f                 # log del servicio
sudo tail -f /home/cowrie/honeypot/var/log/cowrie/cowrie.json   # ataques en directo
# bajar logs (la carpeta de cowrie no es legible para ubuntu: se lee con sudo)
ssh -p 2022 ubuntu@IP 'sudo cat /home/cowrie/honeypot/var/log/cowrie/cowrie.json' > cowrie.json
```
