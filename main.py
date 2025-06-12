import os
import sys
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

import urllib.request
import socket

import netifaces
import psutil

if not os.environ.get("DISPLAY"):
    sys.stderr.write("Error: no se encontró un entorno gráfico (DISPLAY).\n")
    sys.exit(1)

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
        self.geometry("800x480")

        interfaces = self.get_interfaces()
        self.interface_var = tk.StringVar(value=interfaces[0] if interfaces else "")

        # Variables for data
        self.ip_var = tk.StringVar()
        self.gateway_var = tk.StringVar()
        self.dns_var = tk.StringVar()
        self.public_ip_var = tk.StringVar(value="N/A")
        self.speed_var = tk.StringVar()
        self.vlan_var = tk.StringVar()
        self.poe_var = tk.StringVar()
        self.lldp_var = tk.StringVar(value="N/A")

        # VLAN ID for testing
        self.vlan_id_var = tk.StringVar()

        # Track animations for buttons
        self._spinners = {}
        self.update_button = None

        self.update_available = self.check_updates()
        self.create_widgets()
        self.update_public_ip()
        if self.update_available:
            self.after(100, self.show_update_popup)

        # Thread to refresh network data periodically
        threading.Thread(target=self.monitor, daemon=True).start()

    # ------------------------------------------------------------------
    # UI creation
    def create_widgets(self):
        """Create GUI widgets with a Notebook for info and scanning."""

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TLabel", font=("Arial", 16))
        self.style.configure("TButton", font=("Arial", 16), padding=10)
        self.style.configure("TEntry", font=("Arial", 16))
        self.style.configure("TCombobox", font=("Arial", 16))
        self.style.configure("TLabelframe.Label", font=("Arial", 16, "bold"))
        self.style.configure("Small.TLabel", font=("Arial", 12))

        self.style.configure("Local.TFrame", background="#e6f4ff")
        self.style.configure("Local.TLabel", background="#e6f4ff")

        self.style.configure("Internet.TFrame", background="#e8ffe6")
        self.style.configure("Internet.TLabel", background="#e8ffe6")

        self.style.configure("Phys.TFrame", background="#fff4e6")
        self.style.configure("Phys.TLabel", background="#fff4e6")

        self.notebook = ttk.Notebook(self)
        self.info_frame = ttk.Frame(self.notebook)
        self.scan_frame = ttk.Frame(self.notebook)
        self.ping_frame = ttk.Frame(self.notebook)
        self.external_frame = ttk.Frame(self.notebook)
        self.blinker_frame = ttk.Frame(self.notebook)
        self.config_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.info_frame, text="Informaci\u00f3n")
        self.notebook.add(self.scan_frame, text="Escaneo")
        self.notebook.add(self.ping_frame, text="Ping")
        self.notebook.add(self.external_frame, text="Pruebas externas")
        self.notebook.add(self.blinker_frame, text="Port blinker")
        self.notebook.add(self.config_frame, text="Configurar adaptador")
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Network info widgets
        local_frame = ttk.LabelFrame(self.info_frame, text="Red local")
        internet_frame = ttk.LabelFrame(self.info_frame, text="Internet")
        phys_frame = ttk.LabelFrame(self.info_frame, text="Conexi\u00f3n f\u00edsica")
        local_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        internet_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        phys_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        self.info_frame.columnconfigure(0, weight=1)

        local_content = ttk.Frame(local_frame, style="Local.TFrame")
        internet_content = ttk.Frame(internet_frame, style="Internet.TFrame")
        phys_content = ttk.Frame(phys_frame, style="Phys.TFrame")
        for frame in (local_content, internet_content, phys_content):
            frame.grid(row=0, column=0, sticky="nsew")
            frame.columnconfigure(1, weight=1)
        for outer in (local_frame, internet_frame, phys_frame):
            outer.columnconfigure(0, weight=1)

        row = 0
        ttk.Label(local_content, text="Interfaz:", style="Local.TLabel").grid(row=row, column=0, sticky="w", pady=2)
        self.interface_combo = ttk.Combobox(
            local_content,
            textvariable=self.interface_var,
            values=self.get_interfaces(),
            state="readonly",
            width=12,
        )
        self.interface_combo.grid(row=row, column=1, sticky="w", pady=2)
        self.interface_combo.bind("<<ComboboxSelected>>", lambda _e: self.update_info())
        row += 1

        ttk.Label(local_content, text="IP:", style="Local.TLabel").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(local_content, textvariable=self.ip_var, style="Local.TLabel").grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        ttk.Label(local_content, text="Gateway:", style="Local.TLabel").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(local_content, textvariable=self.gateway_var, style="Local.TLabel").grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        ttk.Label(local_content, text="DNS:", style="Local.TLabel").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(local_content, textvariable=self.dns_var, style="Local.TLabel").grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        ttk.Label(local_content, text="VLAN:", style="Local.TLabel").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(local_content, textvariable=self.vlan_var, style="Local.TLabel").grid(row=row, column=1, sticky="w", pady=2)

        ttk.Label(internet_content, text="IP p\u00fablica:", style="Internet.TLabel").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Label(internet_content, textvariable=self.public_ip_var, style="Internet.TLabel").grid(row=0, column=1, sticky="w", pady=2)

        row = 0
        ttk.Label(phys_content, text="Velocidad enlace:", style="Phys.TLabel").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(phys_content, textvariable=self.speed_var, style="Phys.TLabel").grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        ttk.Label(phys_content, text="PoE:", style="Phys.TLabel").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(phys_content, textvariable=self.poe_var, style="Phys.TLabel").grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        ttk.Label(phys_content, text="LLDP/CDP:", style="Phys.TLabel").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(phys_content, textvariable=self.lldp_var, style="Phys.TLabel").grid(row=row, column=1, sticky="w", pady=2)
        self.lldp_button = ttk.Button(
            phys_content, text="Analizar", command=self.detect_neighbors
        )
        self.lldp_button.grid(row=row, column=2, sticky="w", padx=5)

        # Scan widgets
        scan_opts = ttk.Frame(self.scan_frame)
        scan_opts.pack(fill="x", pady=2)

        left_scan = ttk.Frame(scan_opts)
        left_scan.pack(side="left")
        ttk.Label(left_scan, text="VLAN ID (opc.):", style="Small.TLabel").pack(side="left", padx=(0, 5))
        vcmd = (self.register(self.validate_vlan), "%P")
        self.vlan_entry_scan = ttk.Entry(
            left_scan,
            textvariable=self.vlan_id_var,
            validate="key",
            validatecommand=vcmd,
            width=8,
        )
        self.vlan_entry_scan.pack(side="left")

        center_scan = ttk.Frame(scan_opts)
        center_scan.pack(side="left", expand=True, fill="x")
        self.scan_button = ttk.Button(
            center_scan,
            text="Escanear red",
            command=self.scan_network,
            width=14,
        )
        self.scan_button.pack(pady=5)

        columns = ("ip", "mac")
        self.host_tree = ttk.Treeview(self.scan_frame, columns=columns, show="headings", height=8)
        self.host_tree.heading("ip", text="IP")
        self.host_tree.heading("mac", text="MAC")
        self.host_tree.pack(fill="both", expand=True, padx=5, pady=5)

        self.port_button = ttk.Button(self.scan_frame, text="Escanear puertos", command=self.port_scan)
        self.port_button.pack(pady=5)

        self.port_text = tk.Text(self.scan_frame, height=6, font=("Arial", 16))
        self.port_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Ping widgets
        ttk.Label(self.ping_frame, text="Host o IP:").pack(pady=5)
        self.ping_entry = ttk.Entry(self.ping_frame)
        self.ping_entry.pack(fill="x", padx=5)

        ping_opts = ttk.Frame(self.ping_frame)
        ping_opts.pack(fill="x", pady=2)

        left_ping = ttk.Frame(ping_opts)
        left_ping.pack(side="left")
        ttk.Label(left_ping, text="VLAN ID (opc.):", style="Small.TLabel").pack(side="left", padx=(0, 5))
        self.vlan_entry_ping = ttk.Entry(
            left_ping,
            textvariable=self.vlan_id_var,
            validate="key",
            validatecommand=vcmd,
            width=8,
        )
        self.vlan_entry_ping.pack(side="left")

        center_ping = ttk.Frame(ping_opts)
        center_ping.pack(side="left", expand=True, fill="x")
        self.ping_button = ttk.Button(
            center_ping,
            text="Ping",
            command=self.run_ping,
            width=10,
        )
        self.ping_button.pack(pady=5)
        self.ping_text = tk.Text(self.ping_frame, height=8, font=("Arial", 16))
        self.ping_text.pack(fill="both", expand=True, padx=5, pady=5)

        # External tests widgets
        ttk.Label(self.external_frame, text="Host o dominio:").pack(pady=5)
        self.test_host_entry = ttk.Entry(self.external_frame)
        self.test_host_entry.pack(fill="x", padx=5)
        ttk.Label(self.external_frame, text="Puerto:").pack(pady=5)
        self.test_port_entry = ttk.Entry(self.external_frame)
        self.test_port_entry.pack(fill="x", padx=5)
        self.test_button = ttk.Button(
            self.external_frame, text="Probar conexi\u00f3n", command=self.test_connection
        )
        self.test_button.pack(pady=5)
        self.test_output = tk.Text(self.external_frame, height=6, font=("Arial", 16))
        self.test_output.pack(fill="both", expand=True, padx=5, pady=5)

        # Port blinker widgets
        ttk.Label(self.blinker_frame, text="Duraci\u00f3n (s):").pack(pady=5)
        self.blink_seconds_var = tk.StringVar(value="5")
        self.blink_seconds_entry = ttk.Entry(
            self.blinker_frame, textvariable=self.blink_seconds_var
        )
        self.blink_seconds_entry.pack(fill="x", padx=5)
        self.blink_button = ttk.Button(
            self.blinker_frame, text="Parpadear puerto", command=self.blink_port
        )
        self.blink_button.pack(pady=5)
        self.blink_output = tk.Text(self.blinker_frame, height=4, font=("Arial", 16))
        self.blink_output.pack(fill="both", expand=True, padx=5, pady=5)

        # Network configuration widgets
        row = 0
        ttk.Label(self.config_frame, text="Interfaz:").grid(row=row, column=0, sticky="w", pady=2)
        self.config_interface_var = tk.StringVar(value=self.interface_var.get())
        self.config_interface_combo = ttk.Combobox(
            self.config_frame,
            textvariable=self.config_interface_var,
            values=self.get_interfaces(),
            state="readonly",
        )
        self.config_interface_combo.grid(row=row, column=1, sticky="ew", pady=2)
        self.config_interface_combo.bind(
            "<<ComboboxSelected>>", lambda _e: self.load_network_config()
        )
        row += 1

        self.config_mode = tk.StringVar(value="dhcp")
        ttk.Radiobutton(
            self.config_frame,
            text="DHCP",
            variable=self.config_mode,
            value="dhcp",
            command=self.toggle_static_fields,
        ).grid(row=row, column=0, sticky="w")
        ttk.Radiobutton(
            self.config_frame,
            text="Est\u00e1tica",
            variable=self.config_mode,
            value="static",
            command=self.toggle_static_fields,
        ).grid(row=row, column=1, sticky="w")
        row += 1

        ttk.Label(self.config_frame, text="IP:").grid(row=row, column=0, sticky="w", pady=2)
        self.ip_entry = ttk.Entry(self.config_frame)
        self.ip_entry.grid(row=row, column=1, sticky="ew", pady=2)
        row += 1

        ttk.Label(self.config_frame, text="M\u00e1scara:").grid(row=row, column=0, sticky="w", pady=2)
        self.mask_entry = ttk.Entry(self.config_frame)
        self.mask_entry.grid(row=row, column=1, sticky="ew", pady=2)
        row += 1

        ttk.Label(self.config_frame, text="Gateway:").grid(row=row, column=0, sticky="w", pady=2)
        self.gw_entry = ttk.Entry(self.config_frame)
        self.gw_entry.grid(row=row, column=1, sticky="ew", pady=2)
        row += 1

        ttk.Label(self.config_frame, text="DNS:").grid(row=row, column=0, sticky="w", pady=2)
        self.dns_entry = ttk.Entry(self.config_frame)
        self.dns_entry.grid(row=row, column=1, sticky="ew", pady=2)
        row += 1

        self.apply_config_button = ttk.Button(
            self.config_frame, text="Aplicar", command=self.apply_network_config
        )
        self.apply_config_button.grid(row=row, column=0, columnspan=2, pady=5)
        row += 1

        self.config_output = tk.Text(self.config_frame, height=6, font=("Arial", 16))
        self.config_output.grid(row=row, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        self.config_frame.columnconfigure(1, weight=1)
        self.toggle_static_fields()
        self.load_network_config()


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
    def validate_vlan(value):
        """Allow only numeric VLAN IDs in entry widgets."""
        return value.isdigit() or value == ""

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
    def ensure_vlan_interface(base_iface, vlan):
        """Return vlan interface name, creating it if needed."""
        vlan_iface = f"{base_iface}.{vlan}"
        if vlan_iface not in netifaces.interfaces():
            try:
                subprocess.run([
                    "ip",
                    "link",
                    "add",
                    "link",
                    base_iface,
                    "name",
                    vlan_iface,
                    "type",
                    "vlan",
                    "id",
                    vlan,
                ], check=True)
                subprocess.run(["ip", "link", "set", vlan_iface, "up"], check=True)
            except Exception:
                messagebox.showerror(
                    "Error",
                    f"No se pudo crear la interfaz VLAN {vlan_iface}",
                )
                return None
        return vlan_iface

    @staticmethod
    def _is_vlan_interface(iface):
        """Return True if the interface represents a VLAN."""
        if IPRoute is not None:
            try:
                with IPRoute() as ipr:
                    idx = ipr.link_lookup(ifname=iface)
                    if idx:
                        info = ipr.get_links(idx[0])[0]
                        linkinfo = info.get_attr("IFLA_LINKINFO")
                        if linkinfo and linkinfo.get_attr("IFLA_INFO_KIND") == "vlan":
                            return True
            except Exception:
                pass
        return os.path.exists(f"/proc/net/vlan/{iface}")

    @classmethod
    def cleanup_vlan_interfaces(cls):
        """Remove temporary VLAN interfaces left from previous runs."""
        for iface in netifaces.interfaces():
            if "." not in iface:
                continue
            base, suffix = iface.split(".", 1)
            if not suffix.isdigit() or base not in netifaces.interfaces():
                continue
            if cls._is_vlan_interface(iface):
                try:
                    subprocess.run(["ip", "link", "delete", iface], check=True, capture_output=True)
                except Exception:
                    pass

    @staticmethod
    def detect_poe():
        # Placeholder for PoE detection logic
        return "N/A"

    @staticmethod
    def check_updates():
        """Return True if there are commits to pull from origin."""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        git_dir = os.path.join(script_dir, ".git")
        if not os.path.isdir(git_dir):
            return False
        try:
            remotes = subprocess.run(
                ["git", "remote"],
                cwd=script_dir,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            if not remotes:
                return False
            subprocess.run(
                ["git", "fetch", "--quiet"],
                cwd=script_dir,
                check=True,
                capture_output=True,
                text=True,
            )
            branch = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=script_dir,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            local = subprocess.run(
                ["git", "rev-parse", branch],
                cwd=script_dir,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            remote = subprocess.run(
                ["git", "rev-parse", f"origin/{branch}"],
                cwd=script_dir,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            return local != remote
        except subprocess.CalledProcessError:
            return False

    # ------------------------------------------------------------------
    # Button animation helpers
    def _animate_button(self, button):
        info = self._spinners.get(button)
        if not info:
            return
        chars = ["|", "/", "-", "\\"]
        button.config(text=f"{info['base']} {chars[info['phase'] % 4]}")
        info['phase'] += 1
        info['id'] = self.after(200, lambda: self._animate_button(button))

    def start_button_animation(self, button):
        if button in self._spinners:
            return
        self._spinners[button] = {"base": button.cget("text"), "phase": 0}
        button.config(state="disabled")
        self._animate_button(button)

    def stop_button_animation(self, button):
        info = self._spinners.pop(button, None)
        if not info:
            return
        if 'id' in info:
            self.after_cancel(info['id'])
        button.config(text=info['base'], state="normal")

    # ------------------------------------------------------------------
    # Scanning functions
    def scan_network(self):
        """Scan the local network using ARP requests."""
        threading.Thread(target=self._scan_network_thread, daemon=True).start()

    def _scan_network_thread(self):
        self.start_button_animation(self.scan_button)
        self.host_tree.delete(*self.host_tree.get_children())
        iface = self.interface_var.get()
        vlan = self.vlan_id_var.get().strip()
        if vlan:
            vlan_iface = self.ensure_vlan_interface(iface, vlan)
            if not vlan_iface:
                self.stop_button_animation(self.scan_button)
                return
            iface = vlan_iface
            messagebox.showinfo("VLAN", f"Escaneando red en VLAN {vlan}")
        ip = f"{self.get_ip(iface)}/24"
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=ip)
        try:
            ans, _ = srp(ether / arp, timeout=2, iface=iface, verbose=0)
        except PermissionError:
            messagebox.showerror(
                "Permiso denegado",
                "Necesitas privilegios de superusuario para escanear la red",
            )
            self.stop_button_animation(self.scan_button)
            return
        for _, rcv in ans:
            self.host_tree.insert("", "end", values=(rcv.psrc, rcv.hwsrc))
        self.stop_button_animation(self.scan_button)

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
            iface = self.interface_var.get()
            vlan = self.vlan_id_var.get().strip()
            args = None
            if vlan:
                vlan_iface = self.ensure_vlan_interface(iface, vlan)
                if not vlan_iface:
                    return
                args = f"-e {vlan_iface}"
            if args:
                scanner.scan(ip, "1-1024", arguments=args)
            else:
                scanner.scan(ip, "1-1024")
            for proto in scanner[ip].all_protocols():
                for port in sorted(scanner[ip][proto]):
                    state = scanner[ip][proto][port]["state"]
                    self.port_text.insert(tk.END, f"{port}/{proto}: {state}\n")
            if vlan:
                self.port_text.insert(tk.END, f"\n[VLAN {vlan}]\n")
        except Exception as exc:  # pragma: no cover - runtime issues
            self.port_text.insert(tk.END, f"Error: {exc}\n")

    def detect_neighbors(self):
        """Detect LLDP or CDP frames on the selected interface."""
        threading.Thread(target=self._detect_neighbors_thread, daemon=True).start()

    def _detect_neighbors_thread(self):
        self.start_button_animation(self.lldp_button)
        iface = self.interface_var.get()
        result = self.sniff_neighbors(iface)
        self.lldp_var.set(result)
        self.stop_button_animation(self.lldp_button)

    @staticmethod
    def sniff_neighbors(iface):
        try:
            from scapy.all import sniff
            from scapy.contrib import lldp, cdp
        except Exception:
            return "N/A"

        def lfilter(pkt):
            return pkt.haslayer(lldp.LLDPDU) or pkt.haslayer(cdp.CDPMsg)

        try:
            pkts = sniff(iface=iface, timeout=5, count=1, lfilter=lfilter)
        except PermissionError:
            return "Permiso denegado"
        except Exception:
            return "Error"

        if not pkts:
            return "No detectado"
        pkt = pkts[0]

        if pkt.haslayer(lldp.LLDPDU):
            name = None
            port = None
            for tlv in pkt[lldp.LLDPDU].tlv_list:
                if isinstance(tlv, lldp.LLDPDUSystemName):
                    val = tlv.system_name
                    name = val.decode() if isinstance(val, bytes) else val
                elif isinstance(tlv, lldp.LLDPDUPortID):
                    val = tlv.id
                    port = val.decode() if isinstance(val, bytes) else str(val)
            parts = ["LLDP"]
            if name:
                parts.append(name)
            if port:
                parts.append(port)
            return " ".join(parts)

        if pkt.haslayer(cdp.CDPMsg):
            device_layer = pkt.getlayer(cdp.CDPMsgDeviceID)
            port_layer = pkt.getlayer(cdp.CDPMsgPortID)
            device = device_layer.val if device_layer else None
            port = port_layer.iface if port_layer else None
            if isinstance(device, bytes):
                device = device.decode(errors="ignore")
            if isinstance(port, bytes):
                port = port.decode(errors="ignore")
            parts = ["CDP"]
            if device:
                parts.append(device)
            if port:
                parts.append(port)
            return " ".join(parts)

        return "N/A"

    # ------------------------------------------------------------------
    # Port blinker functions
    def blink_port(self):
        secs = self.blink_seconds_var.get().strip()
        self.blink_output.delete("1.0", tk.END)
        try:
            secs = int(secs)
            if secs <= 0:
                raise ValueError
        except ValueError:
            self.blink_output.insert(tk.END, "Tiempo no v\u00e1lido\n")
            return
        self.start_button_animation(self.blink_button)
        threading.Thread(target=self._blink_port_thread, args=(secs,), daemon=True).start()

    def _blink_port_thread(self, secs):
        iface = self.interface_var.get()
        cmd = ["sudo", "ethtool", "-p", iface, str(secs)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
            output = proc.stdout or proc.stderr
            if proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, cmd, output)
        except Exception as exc:
            self.blink_output.insert(tk.END, f"ethtool fall\u00f3: {exc}\n")
            for _ in range(secs):
                subprocess.run(["sudo", "ip", "link", "set", iface, "down"], capture_output=True)
                time.sleep(0.5)
                subprocess.run(["sudo", "ip", "link", "set", iface, "up"], capture_output=True)
                time.sleep(0.5)
            output = "Interfaz alternada para identificar puerto\n"
        self.blink_output.insert(tk.END, output or "\n")
        self.stop_button_animation(self.blink_button)

    # ------------------------------------------------------------------
    # Ping functions
    def run_ping(self):
        host = self.ping_entry.get().strip()
        self.ping_text.delete("1.0", tk.END)
        if not host:
            self.ping_text.insert(tk.END, "Introduce un host\n")
            return
        self.start_button_animation(self.ping_button)
        threading.Thread(target=self._ping_thread, args=(host,), daemon=True).start()

    def _ping_thread(self, host):
        try:
            iface = self.interface_var.get()
            vlan = self.vlan_id_var.get().strip()
            cmd = ["ping", "-c", "4"]
            if vlan:
                vlan_iface = self.ensure_vlan_interface(iface, vlan)
                if not vlan_iface:
                    self.stop_button_animation(self.ping_button)
                    return
                cmd.extend(["-I", vlan_iface])
            cmd.append(host)
            proc = subprocess.run(cmd, capture_output=True, text=True)
            output = proc.stdout or proc.stderr
        except Exception as exc:  # pragma: no cover - runtime issues
            output = str(exc)
        self.ping_text.insert(tk.END, output)
        if vlan:
            self.ping_text.insert(tk.END, f"\n[VLAN {vlan}]\n")
        self.stop_button_animation(self.ping_button)

    # ------------------------------------------------------------------
    # External IP functions
    def update_public_ip(self):
        threading.Thread(target=self._public_ip_thread, daemon=True).start()

    def _public_ip_thread(self):
        ip = self.fetch_external_ip()
        self.public_ip_var.set(ip)

    @staticmethod
    def fetch_external_ip():
        try:
            with urllib.request.urlopen("https://api.ipify.org") as resp:
                return resp.read().decode().strip()
        except Exception:
            return "Error"

    # ------------------------------------------------------------------
    # External connection test
    def test_connection(self):
        host = self.test_host_entry.get().strip()
        port = self.test_port_entry.get().strip()
        self.test_output.delete("1.0", tk.END)
        if not host or not port:
            self.test_output.insert(tk.END, "Indica host y puerto\n")
            return
        try:
            port = int(port)
        except ValueError:
            self.test_output.insert(tk.END, "Puerto no v\u00e1lido\n")
            return
        self.start_button_animation(self.test_button)
        threading.Thread(
            target=self._test_connection_thread,
            args=(host, port),
            daemon=True,
        ).start()

    def _test_connection_thread(self, host, port):
        result = ""
        sock = socket.socket()
        sock.settimeout(3)
        try:
            sock.connect((host, port))
            result = "Puerto abierto"
            try:
                banner = sock.recv(1024)
                if banner:
                    banner = banner.decode(errors="ignore").strip()
                    result += f"\nBanner: {banner}"
            except Exception:
                pass
        except Exception as exc:
            result = f"Puerto cerrado o sin respuesta ({exc})"
        finally:
            sock.close()
        self.test_output.insert(tk.END, result + "\n")
        self.stop_button_animation(self.test_button)

    # ------------------------------------------------------------------
    # Network configuration functions
    def toggle_static_fields(self):
        state = "normal" if self.config_mode.get() == "static" else "disabled"
        for widget in (self.ip_entry, self.mask_entry, self.gw_entry, self.dns_entry):
            widget.configure(state=state)

    def load_network_config(self):
        """Detect current network configuration for the selected interface."""
        conf = self.detect_network_config(self.config_interface_var.get())
        self.config_mode.set(conf["mode"])

        for entry in (self.ip_entry, self.mask_entry, self.gw_entry, self.dns_entry):
            entry.delete(0, tk.END)

        if conf["mode"] == "static":
            if conf["ip"]:
                self.ip_entry.insert(0, conf["ip"])
            if conf["mask"]:
                self.mask_entry.insert(0, conf["mask"])
            if conf["gw"]:
                self.gw_entry.insert(0, conf["gw"])
            if conf["dns"]:
                self.dns_entry.insert(0, conf["dns"])
        self.toggle_static_fields()

    @staticmethod
    def detect_network_config(interface):
        """Return current config from /etc/dhcpcd.conf for an interface."""
        config = {"mode": "dhcp", "ip": "", "mask": "", "gw": "", "dns": ""}
        path = "/etc/dhcpcd.conf"
        if os.path.exists(path):
            try:
                with open(path) as f:
                    lines = [
                        l.strip()
                        for l in f
                        if l.strip() and not l.strip().startswith("#")
                    ]
                for i, line in enumerate(lines):
                    if line.startswith("interface ") and line.split()[1] == interface:
                        for sub in lines[i + 1 :]:
                            if sub.startswith("interface "):
                                break
                            if sub.startswith("static ip_address"):
                                val = sub.split("=", 1)[1].strip()
                                if "/" in val:
                                    ip_part, mask = val.split("/", 1)
                                else:
                                    ip_part, mask = val, ""
                                config["ip"] = ip_part
                                if mask:
                                    if "." in mask:
                                        try:
                                            import ipaddress

                                            mask = str(
                                                ipaddress.ip_network("0.0.0.0/" + mask).prefixlen
                                            )
                                        except Exception:
                                            pass
                                    config["mask"] = mask
                                config["mode"] = "static"
                            elif sub.startswith("static routers"):
                                config["gw"] = sub.split("=", 1)[1].strip()
                            elif sub.startswith("static domain_name_servers"):
                                config["dns"] = sub.split("=", 1)[1].strip()
                        break
            except Exception:
                pass
        return config

    @staticmethod
    def update_dhcpcd_config(iface, mode, ip_addr="", mask="", gw="", dns=""):
        """Write network config to /etc/dhcpcd.conf for persistence."""
        path = "/etc/dhcpcd.conf"
        try:
            lines = []
            if os.path.exists(path):
                with open(path) as f:
                    lines = f.readlines()

            new_lines = []
            i = 0
            while i < len(lines):
                line = lines[i]
                if line.startswith("interface ") and line.split()[1] == iface:
                    i += 1
                    while i < len(lines) and not lines[i].startswith("interface "):
                        i += 1
                    continue
                new_lines.append(line)
                i += 1

            if mode == "static":
                new_lines.append(f"\ninterface {iface}\n")
                new_lines.append(f"static ip_address={ip_addr}/{mask}\n")
                new_lines.append(f"static routers={gw}\n")
                if dns:
                    new_lines.append(f"static domain_name_servers={dns}\n")

            with open(path, "w") as f:
                f.writelines(new_lines)
        except Exception as exc:  # pragma: no cover - filesystem or permission
            return str(exc)
        return ""

    def apply_network_config(self):
        threading.Thread(target=self._apply_config_thread, daemon=True).start()

    def _apply_config_thread(self):
        self.start_button_animation(self.apply_config_button)
        iface = self.config_interface_var.get()
        self.config_output.delete("1.0", tk.END)
        cmds = []
        ip_addr = mask = gw = dns = ""
        if self.config_mode.get() == "dhcp":
            cmds = [["sudo", "dhclient", "-r", iface], ["sudo", "dhclient", iface]]
        else:
            ip_addr = self.ip_entry.get().strip()
            mask = self.mask_entry.get().strip()
            gw = self.gw_entry.get().strip()
            dns = self.dns_entry.get().strip()
            if not ip_addr or not mask or not gw:
                self.config_output.insert(tk.END, "Debes indicar IP, m\u00e1scara y gateway\n")
                self.stop_button_animation(self.apply_config_button)
                return
            cmds = [
                ["sudo", "ip", "addr", "flush", "dev", iface],
                ["sudo", "ip", "addr", "add", f"{ip_addr}/{mask}", "dev", iface],
                ["sudo", "ip", "route", "add", "default", "via", gw],
            ]
            if dns:
                cmds.append([
                    "sudo",
                    "sh",
                    "-c",
                    f"echo nameserver {dns} > /etc/resolv.conf",
                ])
        for cmd in cmds:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True)
                self.config_output.insert(tk.END, proc.stdout + proc.stderr)
            except Exception as exc:  # pragma: no cover - runtime issues
                self.config_output.insert(tk.END, str(exc) + "\n")
        err = self.update_dhcpcd_config(
            iface,
            self.config_mode.get(),
            ip_addr if self.config_mode.get() == "static" else "",
            mask if self.config_mode.get() == "static" else "",
            gw if self.config_mode.get() == "static" else "",
            dns if self.config_mode.get() == "static" else "",
        )
        if err:
            self.config_output.insert(tk.END, f"Error al guardar configuraci\u00f3n: {err}\n")
        self.update_info()
        self.load_network_config()
        self.stop_button_animation(self.apply_config_button)

    def show_update_popup(self):
        popup = tk.Toplevel(self)
        popup.title("Actualizaci\u00f3n disponible")
        ttk.Label(
            popup,
            text="Hay una actualizaci\u00f3n disponible. \u00bfDeseas instalarla?",
        ).pack(padx=20, pady=10)
        btn_frame = ttk.Frame(popup)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Cancelar", command=popup.destroy).pack(
            side="left", padx=5
        )
        self.update_button = ttk.Button(
            btn_frame,
            text="Actualizar",
            command=lambda: self.update_app(popup),
        )
        self.update_button.pack(side="left", padx=5)
        popup.transient(self)
        popup.grab_set()

    def update_app(self, popup):
        """Perform git pull, reinstall dependencies and restart."""
        self.start_button_animation(self.update_button)
        threading.Thread(target=self._update_app_thread, args=(popup,), daemon=True).start()

    def _update_app_thread(self, popup):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        git_dir = os.path.join(script_dir, ".git")

        if not os.path.isdir(git_dir):
            self.after(
                0,
                lambda: messagebox.showerror(
                    "Actualizar",
                    "No se encontró repositorio Git en el directorio de la aplicación",
                ),
            )
            return

        try:
            remotes = subprocess.run(
                ["git", "remote"],
                cwd=script_dir,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        except subprocess.CalledProcessError as exc:
            self.after(0, lambda: messagebox.showerror("Actualizar", f"Error al comprobar remotos: {exc}"))
            return

        if not remotes:
            self.after(0, lambda: messagebox.showerror("Actualizar", "El repositorio no tiene un remoto configurado"))
            return

        try:
            subprocess.run(
                ["sudo", "git", "pull", "--ff-only"],
                cwd=script_dir,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["sudo", "bash", "install.sh"],
                cwd=script_dir,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            output = exc.stderr or exc.stdout or str(exc)
            self.after(0, lambda: self.stop_button_animation(self.update_button))
            self.after(0, lambda: messagebox.showerror("Actualizar", f"Error al actualizar:\n{output}"))
            return

        self.after(0, lambda: self.stop_button_animation(self.update_button))
        self.after(
            0,
            lambda: (
                popup.destroy(),
                messagebox.showinfo(
                    "Actualizar",
                    "Actualización completada. Se reiniciará la aplicación",
                ),
                os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)]),
            ),
        )



def main():
    NetworkMonitor.cleanup_vlan_interfaces()
    app = NetworkMonitor()
    app.mainloop()


if __name__ == "__main__":
    main()

