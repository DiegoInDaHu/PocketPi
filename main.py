import os
import sys
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

import netifaces
import psutil

try:
    import nmap
except ImportError:  # pragma: no cover - optional dependency
    nmap = None

try:
    from pyroute2 import IPRoute
except ImportError:  # pragma: no cover - optional dependency
    IPRoute = None

from scapy.all import ARP, Ether, srp


class NetworkMonitor(tk.Tk):
    """Tkinter GUI to display and scan network information."""

    def __init__(self):
        super().__init__()
        self.title("PocketPi Network Analyzer")
        self.geometry("600x400")

        interfaces = self.get_interfaces()
        self.interface_var = tk.StringVar(value=interfaces[0] if interfaces else "")

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

    # ------------------------------------------------------------------
    # UI creation
    def create_widgets(self):
        """Create GUI widgets with a Notebook for info and scanning."""

        self.style = ttk.Style(self)
        self.style.configure("TLabel", font=("Arial", 11))
        self.style.configure("TButton", font=("Arial", 11))

        notebook = ttk.Notebook(self)
        self.info_frame = ttk.Frame(notebook)
        self.scan_frame = ttk.Frame(notebook)
        self.update_frame = ttk.Frame(notebook)
        notebook.add(self.info_frame, text="Informaci\u00f3n")
        notebook.add(self.scan_frame, text="Escaneo")
        notebook.add(self.update_frame, text="Actualizaci\u00f3n")
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Network info widgets
        row = 0
        ttk.Label(self.info_frame, text="Interfaz:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.OptionMenu(
            self.info_frame,
            self.interface_var,
            self.interface_var.get(),
            *self.get_interfaces(),
            command=lambda _=None: self.update_info(),
        ).grid(row=row, column=1, sticky="ew", pady=2)
        row += 1

        ttk.Label(self.info_frame, text="IP:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(self.info_frame, textvariable=self.ip_var).grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        ttk.Label(self.info_frame, text="Gateway:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(self.info_frame, textvariable=self.gateway_var).grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        ttk.Label(self.info_frame, text="DNS:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(self.info_frame, textvariable=self.dns_var).grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        ttk.Label(self.info_frame, text="Velocidad enlace:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(self.info_frame, textvariable=self.speed_var).grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        ttk.Label(self.info_frame, text="VLAN:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(self.info_frame, textvariable=self.vlan_var).grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        ttk.Label(self.info_frame, text="PoE:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(self.info_frame, textvariable=self.poe_var).grid(row=row, column=1, sticky="w", pady=2)

        # Scan widgets
        self.scan_button = ttk.Button(self.scan_frame, text="Escanear red", command=self.scan_network)
        self.scan_button.pack(pady=5)

        columns = ("ip", "mac")
        self.host_tree = ttk.Treeview(self.scan_frame, columns=columns, show="headings", height=8)
        self.host_tree.heading("ip", text="IP")
        self.host_tree.heading("mac", text="MAC")
        self.host_tree.pack(fill="both", expand=True, padx=5, pady=5)

        self.port_button = ttk.Button(self.scan_frame, text="Escanear puertos", command=self.port_scan)
        self.port_button.pack(pady=5)

        self.port_text = tk.Text(self.scan_frame, height=6)
        self.port_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Update widgets in a separate tab
        ttk.Label(
            self.update_frame,
            text="Comprobar y aplicar actualizaciones"
        ).pack(pady=10)
        self.update_button = ttk.Button(
            self.update_frame,
            text="Actualizar aplicaci\u00f3n",
            command=self.update_app,
        )
        self.update_button.pack(pady=5)

    # ------------------------------------------------------------------
    # Data acquisition
    def monitor(self):
        """Update network info periodically."""
        while True:
            self.update_info()
            time.sleep(3)

    def update_info(self):
        iface = self.interface_var.get()
        self.ip_var.set(self.get_ip(iface))
        self.gateway_var.set(self.get_gateway())
        self.dns_var.set(", ".join(self.get_dns()) or "N/A")
        self.speed_var.set(self.get_link_speed(iface))
        self.vlan_var.set(self.get_vlan(iface))
        self.poe_var.set(self.detect_poe())

    # ------------------------------------------------------------------
    # Utility functions
    @staticmethod
    def get_interfaces():
        return [i for i in netifaces.interfaces() if i != "lo"]

    @staticmethod
    def get_ip(interface):
        try:
            addrs = netifaces.ifaddresses(interface)
            return addrs[netifaces.AF_INET][0]["addr"]
        except (KeyError, IndexError):
            return "Sin conectar"

    @staticmethod
    def get_gateway():
        gws = netifaces.gateways().get("default", {})
        gw = gws.get(netifaces.AF_INET)
        return gw[0] if gw else "N/A"

    @staticmethod
    def get_dns():
        dns = []
        if os.path.exists("/etc/resolv.conf"):
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns.append(line.split()[1])
        return dns

    @staticmethod
    def get_link_speed(interface):
        stats = psutil.net_if_stats().get(interface)
        if stats and stats.isup:
            return f"{stats.speed} Mbps"
        return "N/A"

    @staticmethod
    def get_vlan(interface):
        """Return VLAN ID of the interface or N/A."""
        if IPRoute is not None:
            try:
                with IPRoute() as ipr:
                    idx = ipr.link_lookup(ifname=interface)
                    if idx:
                        info = ipr.get_links(idx[0])[0]
                        linkinfo = info.get_attr("IFLA_LINKINFO")
                        if linkinfo and linkinfo.get_attr("IFLA_INFO_KIND") == "vlan":
                            data = linkinfo.get_attr("IFLA_INFO_DATA")
                            if data:
                                vlan_id = data.get_attr("IFLA_VLAN_ID")
                                return str(vlan_id)
            except Exception:
                pass

        path = f"/proc/net/vlan/{interface}"
        if os.path.exists(path):
            try:
                with open(path) as f:
                    for line in f:
                        if line.strip().startswith("VID:"):
                            return line.split()[1]
            except Exception:
                return interface
        if "." in interface:
            return interface.split(".")[1]
        return "N/A"

    @staticmethod
    def detect_poe():
        # Placeholder for PoE detection logic
        return "N/A"

    # ------------------------------------------------------------------
    # Scanning functions
    def scan_network(self):
        """Scan the local network using ARP requests."""
        self.host_tree.delete(*self.host_tree.get_children())
        iface = self.interface_var.get()
        ip = f"{self.get_ip(iface)}/24"
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=ip)
        try:
            ans, _ = srp(ether / arp, timeout=2, iface=iface, verbose=0)
        except PermissionError:
            messagebox.showerror("Permiso denegado", "Necesitas privilegios de superusuario para escanear la red")
            return
        for _, rcv in ans:
            self.host_tree.insert("", "end", values=(rcv.psrc, rcv.hwsrc))

    def port_scan(self):
        """Scan common ports on the selected host using nmap."""
        selected = self.host_tree.focus()
        if not selected:
            messagebox.showinfo("Informaci\u00f3n", "Seleccione un host para escanear puertos")
            return
        ip = self.host_tree.item(selected)["values"][0]

        self.port_text.delete("1.0", tk.END)
        if nmap is None:
            self.port_text.insert(tk.END, "Biblioteca nmap no disponible\n")
            return

        scanner = nmap.PortScanner()
        try:
            scanner.scan(ip, "1-1024")
            for proto in scanner[ip].all_protocols():
                for port in sorted(scanner[ip][proto]):
                    state = scanner[ip][proto][port]["state"]
                    self.port_text.insert(tk.END, f"{port}/{proto}: {state}\n")
        except Exception as exc:  # pragma: no cover - runtime issues
            self.port_text.insert(tk.END, f"Error: {exc}\n")

    def update_app(self):
        """Perform git pull, reinstall dependencies and restart."""
        if not messagebox.askyesno(
            "Actualizar",
            "\u00bfDeseas buscar e instalar actualizaciones?",
        ):
            return

        script_dir = os.path.dirname(os.path.abspath(__file__))
        try:
            subprocess.run(["sudo", "git", "pull"], cwd=script_dir, check=True)
            subprocess.run(["sudo", "bash", "install.sh"], cwd=script_dir, check=True)
            messagebox.showinfo(
                "Actualizar", "Actualizaci\u00f3n completada. Se reiniciar\u00e1 la aplicaci\u00f3n"
            )
        except subprocess.CalledProcessError as exc:  # pragma: no cover - runtime
            messagebox.showerror(
                "Actualizar", f"Error al actualizar: {exc}"
            )
            return

        os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)])


def main():
    app = NetworkMonitor()
    app.mainloop()


if __name__ == "__main__":
    main()

