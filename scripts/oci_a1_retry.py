#!/usr/bin/env python3
"""
oci_a1_retry.py - Crea la instancia A1.Flex reintentando hasta que haya hueco
Proyecto Intermodular ASIR - Diego Perez Fonterosa

Oracle Cloud responde "Out of host capacity" cuando no quedan maquinas
Always Free A1.Flex en la region. Este script lo vuelve a intentar cada
INTERVALO segundos hasta conseguirla y muestra la IP publica al terminar.

Busca por su cuenta el dominio de disponibilidad, la imagen Ubuntu 24.04
ARM mas reciente y la subnet publica, asi que solo necesita:
  - El fichero ~/.oci/config con una API key (ver pasos en la memoria/README)
  - Tu clave SSH publica

Uso:
  pip install oci
  python oci_a1_retry.py --ssh-key ~/.ssh/id_ed25519.pub
  python oci_a1_retry.py --ssh-key clave.pub --intervalo 90 --ocpus 1 --memoria 6

Avisos al movil (opcional) con ntfy: instala la app ntfy, suscribete a un
tema con nombre dificil de adivinar y pasalo con --ntfy:
  python oci_a1_retry.py --ssh-key clave.pub --ntfy pfc-cowrie-x7k2m9qa
"""

import argparse
import datetime as dt
import os
import random
import sys
import time
import urllib.request

try:
    import oci
except ImportError:
    sys.exit("Falta el SDK de Oracle: ejecuta  pip install oci")

NOMBRE = "honeypot-cowrie"
SHAPE = "VM.Standard.A1.Flex"


def log(msg):
    print(f"[{dt.datetime.now():%H:%M:%S}] {msg}", flush=True)


# --- Avisos con ntfy (https://ntfy.sh) --------------------------------------
NTFY = {"tema": None, "servidor": "https://ntfy.sh"}


def avisar(titulo, mensaje, prioridad="default", etiquetas=""):
    """Envia una notificacion push. Si falla, solo lo registra: nunca para el script."""
    if not NTFY["tema"]:
        return
    req = urllib.request.Request(
        f"{NTFY['servidor'].rstrip('/')}/{NTFY['tema']}",
        data=mensaje.encode("utf-8"),
        headers={"Title": titulo, "Priority": prioridad, "Tags": etiquetas},  # cabeceras ASCII
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=15).close()
    except Exception as e:  # noqa: BLE001 - un aviso fallido no debe detener nada
        log(f"[aviso] No se pudo enviar la notificacion ntfy: {e}")


def fatal(msg):
    log(msg)
    avisar("PFC-Cowrie: script detenido", msg, "high", "warning")
    sys.exit(1)


# --- Descubrimiento de recursos --------------------------------------------
def dominio_disponibilidad(identity, compartment):
    ads = identity.list_availability_domains(compartment).data
    if not ads:
        sys.exit("No se encontro ningun dominio de disponibilidad.")
    return ads[0].name  # Madrid solo tiene uno


def imagen_ubuntu_arm(compute, compartment):
    imgs = compute.list_images(
        compartment,
        operating_system="Canonical Ubuntu",
        operating_system_version="24.04",
        shape=SHAPE,  # solo imagenes compatibles con A1 (aarch64)
        sort_by="TIMECREATED",
        sort_order="DESC",
        lifecycle_state="AVAILABLE",
    ).data
    # Preferir la imagen completa a la "Minimal" (6 GB de RAM sobran)
    completas = [i for i in imgs if "Minimal" not in i.display_name]
    elegida = (completas or imgs or [None])[0]
    if elegida is None:
        sys.exit("No se encontro ninguna imagen Ubuntu 24.04 compatible con A1.Flex.")
    return elegida


def subnet_publica(vnet, compartment, subnet_id=None):
    if subnet_id:
        return vnet.get_subnet(subnet_id).data
    publicas = [
        s for s in oci.pagination.list_call_get_all_results(vnet.list_subnets, compartment).data
        if not s.prohibit_public_ip_on_vnic and s.lifecycle_state == "AVAILABLE"
    ]
    if not publicas:
        sys.exit("No hay ninguna subnet publica. Crea una VCN con el asistente "
                 "'VCN with Internet Connectivity' y vuelve a ejecutar.")
    if len(publicas) > 1:
        print("Hay varias subnets publicas; indica cual con --subnet:")
        for s in publicas:
            print(f"  {s.display_name:30} {s.id}")
        sys.exit(1)
    return publicas[0]


def instancia_existente(compute, compartment):
    for inst in compute.list_instances(compartment, display_name=NOMBRE).data:
        if inst.lifecycle_state not in ("TERMINATED", "TERMINATING"):
            return inst
    return None


def ip_publica(compute, vnet, compartment, instance_id):
    for att in compute.list_vnic_attachments(compartment, instance_id=instance_id).data:
        vnic = vnet.get_vnic(att.vnic_id).data
        if vnic.public_ip:
            return vnic.public_ip
    return None


# --- Programa principal ----------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Reintenta crear la instancia A1.Flex Always Free")
    ap.add_argument("--ssh-key", required=True, help="Ruta a tu clave SSH PUBLICA (.pub)")
    ap.add_argument("--intervalo", type=int, default=60, help="Segundos entre intentos (defecto 60)")
    ap.add_argument("--ocpus", type=float, default=1, help="OCPUs (defecto 1, maximo gratis 4)")
    ap.add_argument("--memoria", type=float, default=6, help="GB de RAM (defecto 6, maximo gratis 24)")
    ap.add_argument("--subnet", help="OCID de la subnet si hay varias publicas")
    ap.add_argument("--config", default="~/.oci/config", help="Fichero de configuracion OCI")
    ap.add_argument("--perfil", default="DEFAULT", help="Perfil dentro del fichero de configuracion")
    ap.add_argument("--ntfy", metavar="TEMA", help="Tema de ntfy para recibir avisos en el movil")
    ap.add_argument("--ntfy-servidor", default="https://ntfy.sh", help=argparse.SUPPRESS)
    args = ap.parse_args()
    NTFY["tema"], NTFY["servidor"] = args.ntfy, args.ntfy_servidor

    ssh_path = os.path.expanduser(args.ssh_key)
    if not ssh_path.endswith(".pub"):
        sys.exit("--ssh-key debe ser la clave PUBLICA (fichero .pub), nunca la privada.")
    with open(ssh_path, encoding="utf-8") as f:
        ssh_key = f.read().strip()

    config = oci.config.from_file(os.path.expanduser(args.config), args.perfil)
    oci.config.validate_config(config)
    compartment = config["tenancy"]  # compartment raiz

    identity = oci.identity.IdentityClient(config)
    compute = oci.core.ComputeClient(config)
    vnet = oci.core.VirtualNetworkClient(config)

    ya = instancia_existente(compute, compartment)
    if ya:
        log(f"Ya existe '{NOMBRE}' en estado {ya.lifecycle_state}. No se crea otra.")
        sys.exit(0)

    ad = dominio_disponibilidad(identity, compartment)
    img = imagen_ubuntu_arm(compute, compartment)
    sub = subnet_publica(vnet, compartment, args.subnet)
    log(f"Dominio:  {ad}")
    log(f"Imagen:   {img.display_name}")
    log(f"Subnet:   {sub.display_name}")
    log(f"Forma:    {SHAPE} ({args.ocpus:g} OCPU, {args.memoria:g} GB)")
    if NTFY["tema"]:
        avisar("PFC-Cowrie: script en marcha",
               f"Buscando hueco para {SHAPE} cada {args.intervalo} s. "
               "Si te llega este aviso, las notificaciones funcionan.", "low", "hourglass")
        log(f"Avisos ntfy activados en el tema '{NTFY['tema']}'.")

    detalles = oci.core.models.LaunchInstanceDetails(
        availability_domain=ad,
        compartment_id=compartment,
        display_name=NOMBRE,
        shape=SHAPE,
        shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
            ocpus=args.ocpus, memory_in_gbs=args.memoria),
        source_details=oci.core.models.InstanceSourceViaImageDetails(image_id=img.id),
        create_vnic_details=oci.core.models.CreateVnicDetails(
            subnet_id=sub.id, assign_public_ip=True),
        metadata={"ssh_authorized_keys": ssh_key},
    )

    intento = 0
    espera = args.intervalo
    while True:
        intento += 1
        try:
            resp = compute.launch_instance(detalles)
            break
        except oci.exceptions.ServiceError as e:
            msg = (e.message or "").lower()
            if e.status == 500 and "capacity" in msg:
                log(f"Intento {intento}: sin capacidad. Reintento en {espera} s.")
                espera = args.intervalo
            elif e.status == 429:
                espera = min(espera * 2, 600)  # Oracle pide frenar: esperar mas
                log(f"Intento {intento}: demasiadas peticiones. Reintento en {espera} s.")
            elif e.status >= 500:
                log(f"Intento {intento}: error temporal de Oracle ({e.code}). Reintento en {espera} s.")
            else:
                # Errores de configuracion o limites: reintentar no sirve
                fatal(f"Error {e.status} {e.code}: {e.message}")
        except (oci.exceptions.RequestException, ConnectionError) as e:
            log(f"Intento {intento}: fallo de red ({type(e).__name__}). Reintento en {espera} s.")
        time.sleep(espera + random.randint(0, 10))

    inst = resp.data
    log(f"Instancia creada tras {intento} intentos. Esperando a que arranque...")
    inst = oci.wait_until(compute, compute.get_instance(inst.id), "lifecycle_state",
                          "RUNNING", max_wait_seconds=900).data
    ip = ip_publica(compute, vnet, compartment, inst.id)

    print("\n" + "=" * 60)
    print("  INSTANCIA LISTA")
    print(f"  Nombre: {inst.display_name}")
    print(f"  IP:     {ip}")
    print(f"  Conexion:  ssh -i <tu_clave_privada> ubuntu@{ip}")
    print("=" * 60)
    print("\a")  # pitido
    avisar("PFC-Cowrie: INSTANCIA LISTA",
           f"{inst.display_name} creada tras {intento} intentos.\n"
           f"IP publica: {ip}\nssh ubuntu@{ip}", "urgent", "tada")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Detenido por el usuario.")
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - avisar de cualquier fallo inesperado
        log(f"Error inesperado: {type(e).__name__}: {e}")
        avisar("PFC-Cowrie: script detenido", f"Error inesperado: {type(e).__name__}: {e}", "high", "warning")
        raise
