import os
import sys
import json
import logging
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, IP, TCP, UDP


#Log function
logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s : %(message)s %(filename)s')

#Editing rules in rules.json
def load_rules():
    default = {
        "block_ips":[],
        "block_ports":[],
        "allow_protocols":[],
        "custom_rules":[]
    }
    if os.path.exists("rules.json"):
        with open("rules.json", 'r') as f:
            data = json.load(f)
            for key in default:
                if key not in data:
                    data[key] = default[key]
            return data
    return default

def save_rules(rules):
    with open("rules.json", 'w') as f:
        json.dump(rules, f, indent=4)

def apply_rule(rule):
    try:
        command = ['sudo'] + rule.split()
        subprocess.run(command, check=True)
        logging.info(f"Applied rule: {rule}")
        messagebox.showinfo("Sucess", f"Rule applied: {rule}")
    except subprocess.CalledProcessError:
        logging.error(f"Failed to apply rule: {rule}")
        messagebox.showerror("Error",f"Failed to apply rule:\n{rule}")

def is_blocked(packet,rules):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        
        #Checking IP
        if src_ip in rules["block_ips"]:
            return f"Blocked IP : {src_ip}"
        #Checking Port
        if TCP in packet:
            src_port = packet.sport
            dst_port = packet.dport
        elif  UDP in packet:
            src_port = packet.sport
            dst_port = packet.dport
        else:
            src_port = dst_port = None
        
        if src_port in rules ["block_ports"] or dst_port in rules["block_ports"]:
                return f"Blocked Port : {src_port}->{dst_port}"
            
        #Checking Protocol
        if TCP in packet and "TCP" not in rules["allow_protocols"]:
            return "TCP is not allowed"
        if UDP in packet and "UDP" not in rules["allow_protocols"]:
            return "UDP is not allowed"
    
    return None

#Log blocked packets
def log_block(reason,packet):
    logging.info(f"{reason} | {packet.summary()}")
    
def enforce_iptables_block(ip):
    subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

#Packet Handler
def packet_handler(packet):
    rules = load_rules()
    reason = is_blocked(packet, rules)
    if reason:
        log_block(reason, packet)
        print(f"[!] {reason}")

def start_sniffing():
    try:
        print("Starting Firewall...")
        sniff(prn=packet_handler, store=0)
    except PermissionError:
        print("[!] Permission denied. Please run as root.")
        sys.exit(1)

def add_rule():
    rule = rule_entry.get()
    if not rule:
        messagebox.showwarning("Warning", "Please enter a rule")
        return
    
    rules = load_rules()
    rules["custom_rules"].append(rule)
    save_rules(rules)
    apply_rule(rule)
    rule_entry.delete(0, tk.END)
    refresh_rule_list()
        
def refresh_rule_list():
    rule_list.delete(0, tk.END)
    rules = load_rules()
    for rule in rules["custom_rules"]:
        rule_list.insert(tk.END, rule)

def delete_selected_rule():
    selected = rule_list.curselection()
    if selected:
        index = selected[0]
        rules = load_rules()
        deleted_rule = rules["custom_rules"].pop(index)
        save_rules(rules)
        logging.info(f"Deleted rule: {deleted_rule}")
        refresh_rule_list()
    else:
        messagebox.showinfo("Info", "Select a rule to delete.")

if os.name == 'nt':
    import ctypes
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    def run_as_admin():
        if not is_admin():
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
            sys.exit()
    run_as_admin()

elif os.name == 'posix':
    def elevate_to_root():
        if os.geteuid() != 0:
            print("[!] Not root. Restarting with sudo...")
            os.execvp('sudo', ['sudo', 'python3'] + sys.argv)
    elevate_to_root()

#------GUI------#
root = tk.Tk()
root.title("Python Firewall")
root.geometry("500x500")
tk.Label(root, text="Montioring Traffic...", height="5").pack()

tk.Label(root, text="Enter iptables rule (without 'sudo')").pack(pady=5)
rule_entry = tk.Entry(root, width=30)
rule_entry.pack(pady=5)

tk.Button(root, text="Add Rule",height="1", command=add_rule).pack(pady=5)

tk.Label(root, text="Saved Firewall Rules").pack(pady=5)
rule_list = tk.Listbox(root, width=60)
rule_list.pack(pady=5)

tk.Button(root, text="Delete Selected Rule", command=delete_selected_rule).pack(pady=5)

tk.Button(root, text="Refresh Rule List", command=refresh_rule_list).pack(pady=5)

threading.Thread(target=start_sniffing, daemon=True).start()
root.mainloop()
