import os
import threading
import time
import tkinter as tk
from tkinter import ttk

import netifaces
import psutil


class NetworkMonitor(tk.Tk):
    """Tkinter GUI to display network information."""

    def __init__(self, interface="eth0"):
        super().__init__()
        self.interface = interface
        self.title("PocketPi Network Analyzer")
        self.geometry("480x320")

        # Variables for data
        self.ip_var = tk.StringVar()
        self.gateway_var = tk.StringVar()
        self.dns_var = tk.StringVar()
        self.speed_var = tk.StringVar()
        self.vlan_var = tk.StringVar()
        self.poe_var = tk.StringVar()

        self.create_widgets()

        # Thread to refresh network data periodically
        threading.Thread(target=self.monitor, daemon=True).start()

    def create_widgets(self):
        """Create GUI widgets."""
        row = 0
        ttk.Label(self, text="IP:").grid(row=row, column=0, sticky="w")
        ttk.Label(self, textvariable=self.ip_var).grid(row=row, column=1, sticky="w")
        row += 1

        ttk.Label(self, text="Gateway:").grid(row=row, column=0, sticky="w")
        ttk.Label(self, textvariable=self.gateway_var).grid(row=row, column=1, sticky="w")
        row += 1

        ttk.Label(self, text="DNS:").grid(row=row, column=0, sticky="w")
        ttk.Label(self, textvariable=self.dns_var).grid(row=row, column=1, sticky="w")
        row += 1

        ttk.Label(self, text="Velocidad enlace:").grid(row=row, column=0, sticky="w")
        ttk.Label(self, textvariable=self.speed_var).grid(row=row, column=1, sticky="w")
        row += 1

        ttk.Label(self, text="VLAN:").grid(row=row, column=0, sticky="w")
        ttk.Label(self, textvariable=self.vlan_var).grid(row=row, column=1, sticky="w")
        row += 1

        ttk.Label(self, text="PoE:").grid(row=row, column=0, sticky="w")
        ttk.Label(self, textvariable=self.poe_var).grid(row=row, column=1, sticky="w")
        row += 1

        ttk.Button(self, text="Escanear red", command=self.scan_network).grid(
            row=row, column=0, columnspan=2, pady=10
        )
        row += 1

        self.result_box = tk.Text(self, height=8)
        self.result_box.grid(row=row, column=0, columnspan=2, sticky="nsew")

    def monitor(self):
        """Update network info periodically."""
        while True:
            self.update_info()
            time.sleep(3)

    def update_info(self):
        self.ip_var.set(self.get_ip())
        self.gateway_var.set(self.get_gateway())
        self.dns_var.set(", ".join(self.get_dns()) or "N/A")
        self.speed_var.set(self.get_link_speed())
        self.vlan_var.set(self.get_vlan())
        self.poe_var.set(self.detect_poe())

    def get_ip(self):
        try:
            addrs = netifaces.ifaddresses(self.interface)
            return addrs[netifaces.AF_INET][0]["addr"]
        except (KeyError, IndexError):
            return "Sin conectar"

    def get_gateway(self):
        gws = netifaces.gateways().get("default", {})
        gw = gws.get(netifaces.AF_INET)
        return gw[0] if gw else "N/A"

    def get_dns(self):
        dns = []
        if os.path.exists("/etc/resolv.conf"):
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns.append(line.split()[1])
        return dns

    def get_link_speed(self):
        stats = psutil.net_if_stats().get(self.interface)
        if stats and stats.isup:
            return f"{stats.speed} Mbps"
        return "N/A"

    def get_vlan(self):
        path = f"/proc/net/vlan/{self.interface}"
        if os.path.exists(path):
            return self.interface
        if "." in self.interface:
            return self.interface.split(".")[1]
        return "N/A"

    def detect_poe(self):
        # Placeholder for PoE detection logic
        return "N/A"

    def scan_network(self):
        self.result_box.delete("1.0", tk.END)
        try:
            from scapy.all import ARP, Ether, srp

            ip = f"{self.get_ip()}/24"
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(pdst=ip)
            ans, _ = srp(ether / arp, timeout=2, iface=self.interface, verbose=0)
            hosts = [f"{rcv.psrc} {rcv.hwsrc}" for _, rcv in ans]
            if hosts:
                self.result_box.insert(tk.END, "\n".join(hosts))
            else:
                self.result_box.insert(tk.END, "Sin resultados")
        except Exception as exc:
            self.result_box.insert(tk.END, f"Error: {exc}")


def main():
    app = NetworkMonitor()
    app.mainloop()


if __name__ == "__main__":
    main()
