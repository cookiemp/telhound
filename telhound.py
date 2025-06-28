import sys
import psutil
import socket
import time
import ipaddress
import os
import subprocess
import webbrowser
import ctypes
import sqlite3

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
from PySide6.QtWidgets import (QApplication, QMainWindow, QTableWidget, 
                               QTableWidgetItem, QHeaderView, QStatusBar, 
                               QMenu, QVBoxLayout, QWidget, QLineEdit, 
                               QMessageBox, QTabWidget, QPushButton, QHBoxLayout,
                               QListWidget)
from PySide6.QtCore import QThread, Signal, Qt, QSettings
from PySide6.QtGui import QColor, QAction, QIcon # <-- IMPORTED QIcon

# --- NEW: Helper function to find bundled resources ---
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- Helper function and Constants (Unchanged) ---
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

BLOCKLIST_FILENAME = "blocklist.txt"

# --- Connection Worker Thread (Unchanged) ---
class ConnectionWorker(QThread):
    new_connection = Signal(tuple)
    status_update = Signal(str)
    
    def __init__(self, blocklist_set):
        super().__init__()
        self._is_running = True
        self.known_connections = set()
        self.telemetry_blocklist = blocklist_set

    def run(self):
        process_cache, ip_cache = {}, {}
        while self._is_running:
            self.status_update.emit("Scanning for network connections...")
            try: connections = psutil.net_connections(kind='inet')
            except psutil.AccessDenied: self.status_update.emit("Access Denied. Run as admin."); time.sleep(5); continue
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    pid, (r_ip, r_port) = conn.pid, conn.raddr
                    conn_key = (pid, r_ip, r_port)
                    if conn_key in self.known_connections: continue
                    if pid:
                        if pid not in process_cache:
                            try: process_cache[pid] = psutil.Process(pid).name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied): process_cache[pid] = "N/A"
                        proc_name = process_cache[pid]
                        if r_ip not in ip_cache:
                            hostname, owner = "N/A (No Reverse DNS)", "N/A"
                            try:
                                ip_obj = ipaddress.ip_address(r_ip)
                                if ip_obj.is_private or ip_obj.is_loopback: hostname, owner = "Local Network", "Private"
                                else:
                                    try: hostname = socket.gethostbyaddr(r_ip)[0]
                                    except (socket.herror, socket.gaierror): pass
                                    self.status_update.emit(f"Performing Whois lookup for {r_ip}...")
                                    try: owner = IPWhois(r_ip).lookup_rdap().get('asn_description', 'N/A')
                                    except Exception: owner = "Whois Failed"
                            except ValueError: hostname, owner = "Invalid IP", "Invalid IP"
                            ip_cache[r_ip] = {'hostname': hostname, 'owner': owner}
                        hostname, owner = ip_cache[r_ip]['hostname'], ip_cache[r_ip]['owner']
                        is_suspicious, suspicion_reason = False, ""
                        for domain in self.telemetry_blocklist:
                            if domain in hostname: is_suspicious, suspicion_reason = True, f"Reason: Hostname on blocklist."; break
                        if not is_suspicious and "MICROSOFT" in owner.upper(): is_suspicious, suspicion_reason = True, f"Reason: IP owned by '{owner}'."
                        self.known_connections.add(conn_key)
                        self.new_connection.emit((proc_name, pid, hostname, owner, r_ip, r_port, is_suspicious, suspicion_reason))
            self.status_update.emit(f"Idle... Waiting for next scan. (Last check: {time.strftime('%H:%M:%S')})")
            time.sleep(3)
    def stop(self): self._is_running = False

# --- Main Window with New Color ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.is_admin_session = is_admin()
        admin_title = "🛡️" if self.is_admin_session else "(Limited)"
        self.setWindowTitle(f"TELHOUND v1.7.0 - Network Monitor {admin_title}")
        
        # --- NEW: Set the window and taskbar icon ---
        self.setWindowIcon(QIcon(resource_path("icon.ico")))
        
        # --- NEW: Define the highlight color as an instance attribute ---
        self.SUSPICIOUS_COLOR = QColor(255, 128, 128) # A more distinct red
        
        self.settings = QSettings("TELHOUND_dev", "TELHOUND")
        self.permanent_status_message = "Initializing..."
        self.setup_ui()
        self.blocklist_set = self.load_or_create_blocklist()
        self.db_conn = self.init_database()
        self.start_worker()

    def add_connection_to_table(self, connection_data):
        self.log_connection_to_db(connection_data)
        proc_name, pid, hostname, owner, r_ip, r_port, is_suspicious, suspicion_reason = connection_data
        row_pos = self.live_table.rowCount()
        self.live_table.insertRow(row_pos)
        items = [QTableWidgetItem(proc_name), QTableWidgetItem(str(pid)), QTableWidgetItem(hostname), QTableWidgetItem(owner), QTableWidgetItem(r_ip), QTableWidgetItem(str(r_port))]
        if is_suspicious:
            # MODIFIED: Use the defined color
            for item in items:
                item.setBackground(self.SUSPICIOUS_COLOR)
                item.setToolTip(suspicion_reason)
        for col, item in enumerate(items):
            self.live_table.setItem(row_pos, col, item)

    def populate_history_table(self):
        self.show_temporary_status("Loading history...", 1000)
        self.history_table.setRowCount(0)
        if not self.db_conn: return
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT timestamp, process_name, pid, hostname, owner, ip_address, port, is_suspicious FROM connections ORDER BY timestamp DESC LIMIT 1000")
            records = cursor.fetchall()
            self.history_table.setSortingEnabled(False)
            for row_num, row_data in enumerate(records):
                self.history_table.insertRow(row_num)
                is_suspicious_flag = row_data[7] == 1
                for col_num, data in enumerate(row_data[:-1]):
                    item = QTableWidgetItem(str(data))
                    # MODIFIED: Use the defined color
                    if is_suspicious_flag:
                        item.setBackground(self.SUSPICIOUS_COLOR)
                    self.history_table.setItem(row_num, col_num, item)
            self.history_table.setSortingEnabled(True)
            self.filter_history_table()
            self.show_temporary_status(f"Loaded {len(records)} records.", 3000)
        except sqlite3.Error as e:
            self.show_temporary_status(f"Error loading history: {e}", 5000)

    # --- (All other methods are unchanged) ---
    def setup_ui(self):
        self.tabs = QTabWidget(); self.setCentralWidget(self.tabs)
        self.create_live_tab(); self.create_history_tab(); self.create_blocklist_tab()
        self.tabs.addTab(self.live_tab, "Live Connections"); self.tabs.addTab(self.history_tab, "Connection History"); self.tabs.addTab(self.blocklist_tab, "Manage Blocklist")
        self.tabs.currentChanged.connect(self.on_tab_change)
        self.status_bar = QStatusBar(); self.setStatusBar(self.status_bar)
        geometry = self.settings.value("geometry"); self.restoreGeometry(geometry) if geometry else self.setGeometry(100, 100, 1100, 700)
        self.resize_tables()
    def create_live_tab(self):
        self.live_tab = QWidget(); layout = QVBoxLayout(self.live_tab)
        self.live_filter_box = QLineEdit(); self.live_filter_box.setPlaceholderText("Filter live connections..."); self.live_filter_box.textChanged.connect(self.filter_live_table)
        self.live_table = QTableWidget(); self.live_table.setColumnCount(6); self.live_table.setHorizontalHeaderLabels(["Process Name", "PID", "Destination Hostname", "Owner", "Destination IP", "Port"]); self.live_table.setContextMenuPolicy(Qt.CustomContextMenu); self.live_table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.live_filter_box); layout.addWidget(self.live_table)
    def create_history_tab(self):
        self.history_tab = QWidget(); layout = QVBoxLayout(self.history_tab)
        self.history_filter_box = QLineEdit(); self.history_filter_box.setPlaceholderText("Filter historical connections..."); self.history_filter_box.textChanged.connect(self.filter_history_table)
        self.refresh_history_button = QPushButton("🔄 Refresh History"); self.refresh_history_button.clicked.connect(self.populate_history_table)
        self.history_table = QTableWidget(); self.history_table.setColumnCount(7); self.history_table.setHorizontalHeaderLabels(["Timestamp", "Process Name", "PID", "Hostname", "Owner", "IP Address", "Port"]); self.history_table.setSortingEnabled(True)
        top_layout = QHBoxLayout(); top_layout.addWidget(self.history_filter_box); top_layout.addWidget(self.refresh_history_button)
        layout.addLayout(top_layout); layout.addWidget(self.history_table)
    def create_blocklist_tab(self):
        self.blocklist_tab = QWidget(); layout = QVBoxLayout(self.blocklist_tab)
        add_layout = QHBoxLayout()
        self.blocklist_input = QLineEdit(); self.blocklist_input.setPlaceholderText("Enter a domain to block (e.g., tracking.example.com)")
        self.blocklist_add_button = QPushButton("➕ Add"); self.blocklist_add_button.clicked.connect(self.add_to_blocklist_ui)
        add_layout.addWidget(self.blocklist_input); add_layout.addWidget(self.blocklist_add_button)
        self.blocklist_list_widget = QListWidget()
        bottom_layout = QHBoxLayout()
        self.blocklist_remove_button = QPushButton("➖ Remove Selected"); self.blocklist_remove_button.clicked.connect(self.remove_from_blocklist_ui)
        self.blocklist_save_button = QPushButton("💾 Save Blocklist"); self.blocklist_save_button.clicked.connect(self.save_blocklist_file)
        bottom_layout.addWidget(self.blocklist_remove_button); bottom_layout.addStretch(); bottom_layout.addWidget(self.blocklist_save_button)
        layout.addLayout(add_layout); layout.addWidget(self.blocklist_list_widget); layout.addLayout(bottom_layout)
    def load_or_create_blocklist(self):
        if not os.path.exists(BLOCKLIST_FILENAME):
            self.show_temporary_status(f"No {BLOCKLIST_FILENAME} found, creating default.")
            default_blocklist = {"vortex.data.microsoft.com","vortex-win.data.microsoft.com","telemetry.microsoft.com","watson.telemetry.microsoft.com","settings-win.data.microsoft.com","oca.telemetry.microsoft.com","services.weserv.nl","self.events.data.microsoft.com","telemetry.nvidia.com","gfe.nvidia.com","tools.google.com","clients1.google.com","telemetry.mozilla.org","metrics.adobedtm.com"}
            try:
                with open(BLOCKLIST_FILENAME, 'w') as f:
                    for domain in sorted(list(default_blocklist)): f.write(f"{domain}\n")
            except IOError as e: QMessageBox.critical(self, "File Error", f"Could not create default blocklist.\nError: {e}"); return set()
        try:
            with open(BLOCKLIST_FILENAME, 'r') as f:
                return {line.strip() for line in f if line.strip() and not line.strip().startswith('#')}
        except IOError as e: QMessageBox.critical(self, "File Error", f"Could not read blocklist.\nError: {e}"); return set()
    def add_to_blocklist_ui(self):
        domain = self.blocklist_input.text().strip().lower()
        if not domain: return
        if not self.blocklist_list_widget.findItems(domain, Qt.MatchFlag.MatchExactly):
            self.blocklist_list_widget.addItem(domain); self.blocklist_list_widget.sortItems()
            self.blocklist_input.clear(); self.show_temporary_status(f"Added '{domain}'. Don't forget to save.", 3000)
        else: self.show_temporary_status(f"'{domain}' is already in the list.", 2000)
    def remove_from_blocklist_ui(self):
        selected_items = self.blocklist_list_widget.selectedItems()
        if not selected_items: self.show_temporary_status("No items selected.", 2000); return
        for item in selected_items: self.blocklist_list_widget.takeItem(self.blocklist_list_widget.row(item))
        self.show_temporary_status("Removed items. Don't forget to save.", 3000)
    def save_blocklist_file(self):
        if QMessageBox.question(self, 'Confirm Save', "Overwrite blocklist.txt?\nA restart is required for changes to take effect.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) == QMessageBox.StandardButton.No:
            self.show_temporary_status("Save cancelled."); return
        try:
            with open(BLOCKLIST_FILENAME, 'w') as f:
                for i in range(self.blocklist_list_widget.count()): f.write(f"{self.blocklist_list_widget.item(i).text()}\n")
            self.show_temporary_status("✅ Blocklist saved. Please restart the application.", 5000)
        except IOError as e: QMessageBox.critical(self, "File Error", f"Could not save blocklist.\nError: {e}")
    def start_worker(self):
        self.blocklist_list_widget.addItems(sorted(list(self.blocklist_set)))
        self.worker = ConnectionWorker(self.blocklist_set); self.worker.new_connection.connect(self.add_connection_to_table); self.worker.status_update.connect(self.set_permanent_status); self.worker.start()
        self.set_permanent_status("TELHOUND is running...")
    def set_permanent_status(self, message): self.permanent_status_message = message; self.status_bar.showMessage(self.permanent_status_message)
    def show_temporary_status(self, message, timeout=2000): self.status_bar.showMessage(message, timeout)
    def on_tab_change(self, index):
        if index == 1: self.populate_history_table()
        elif index == 2: self.show_temporary_status("Changes must be saved and app restarted to take effect.", 4000)
        else: self.set_permanent_status(self.permanent_status_message)
    def resize_tables(self):
        for table in [self.live_table, self.history_table]:
            header = table.horizontalHeader()
            if table is self.live_table: header.setSectionResizeMode(QHeaderView.ResizeToContents); header.setSectionResizeMode(2, QHeaderView.Stretch); header.setSectionResizeMode(3, QHeaderView.Stretch)
            else: header.setSectionResizeMode(QHeaderView.Stretch); header.setSectionResizeMode(0, QHeaderView.ResizeToContents); header.setSectionResizeMode(2, QHeaderView.ResizeToContents); header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
    def init_database(self):
        try:
            conn = sqlite3.connect('telhound_log.db'); cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS connections ( id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            process_name TEXT, pid INTEGER, hostname TEXT, owner TEXT, ip_address TEXT, port INTEGER, is_suspicious INTEGER, suspicion_reason TEXT )''')
            conn.commit(); return conn
        except sqlite3.Error as e: QMessageBox.critical(self, "Database Error", f"Could not initialize database.\nError: {e}"); return None
    def log_connection_to_db(self, d):
        if not self.db_conn: return
        p, i, h, o, ip, pt, s, r = d
        try: c=self.db_conn.cursor(); c.execute('''INSERT INTO connections(process_name, pid, hostname, owner, ip_address, port, is_suspicious, suspicion_reason) VALUES(?,?,?,?,?,?,?,?)''', (p,i,h,o,ip,pt,int(s),r)); self.db_conn.commit()
        except sqlite3.Error as e: print(f"DB write error: {e}")
    def filter_live_table(self):
        t=self.live_filter_box.text().lower(); [self.live_table.setRowHidden(r, t not in ''.join(self.live_table.item(r,c).text().lower()+' ' for c in range(self.live_table.columnCount()) if self.live_table.item(r,c))) for r in range(self.live_table.rowCount())]
    def filter_history_table(self):
        t=self.history_filter_box.text().lower(); [self.history_table.setRowHidden(r, t not in ''.join(self.history_table.item(r,c).text().lower()+' ' for c in range(self.history_table.columnCount()) if self.history_table.item(r,c))) for r in range(self.history_table.rowCount())]
    def show_context_menu(self, pos):
        item=self.live_table.itemAt(pos);
        if not item: return
        r=item.row(); p=self.live_table.item(r,0).text(); pid=self.live_table.item(r,1).text(); h=self.live_table.item(r,2).text(); ip=self.live_table.item(r,4).text()
        menu=QMenu(self);
        a1=QAction(f"Copy IP ({ip})",self); a2=QAction(f"Copy Hostname ({h})",self); a3=QAction("Show File Location",self); a4=QAction(f"Look up '{p}'",self)
        a1.triggered.connect(lambda:self.copy_to_clipboard(ip)); a2.triggered.connect(lambda:self.copy_to_clipboard(h)); a3.triggered.connect(lambda:self.show_file_location(int(pid))); a4.triggered.connect(lambda:self.search_process_online(p))
        menu.addActions([a1,a2]); menu.addSeparator(); menu.addActions([a3,a4]); menu.addSeparator()
        ba=QAction(f"🛡️ Block Connection to {ip}",self); (not self.is_admin_session or pid=="N/A" or p=="N/A") and ba.setEnabled(False) or ba.setToolTip("Run as admin for this feature."); ba.triggered.connect(lambda:self.block_connection(int(pid),p,ip)); menu.addAction(ba)
        menu.exec(self.live_table.mapToGlobal(pos)); self.set_permanent_status(self.permanent_status_message)
    def block_connection(self,pid,p,ip):
        try: ep=psutil.Process(pid).exe()
        except(psutil.NoSuchProcess,psutil.AccessDenied) as e: self.show_temporary_status(f"Error: Could not get path. {e}",4000); return
        if QMessageBox.question(self,'Confirm Block',f"Block:\n{p}\nFrom connecting to IP: {ip}?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)==QMessageBox.StandardButton.No: self.show_temporary_status("Block cancelled."); return
        self.show_temporary_status(f"Adding firewall rule...",3000); rn=f"TELHOUND-Block-{os.path.basename(ep)}-{ip}"; cmd=['netsh','advfirewall','firewall','add','rule',f'name="{rn}"','dir=out',f'program="{ep}"',f'remoteip="{ip}"','action=block'];
        try: subprocess.run(cmd,check=True,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW); self.show_temporary_status(f"✅ Successfully blocked {p}.",5000)
        except Exception as e: QMessageBox.critical(self,"Firewall Error",f"Could not create rule.\nError: {e}")
    def copy_to_clipboard(self,t): QApplication.clipboard().setText(t); self.show_temporary_status(f"Copied '{t}' to clipboard.")
    def show_file_location(self,p):
        try: subprocess.run(['explorer','/select,',psutil.Process(p).exe()],check=True); self.show_temporary_status("Opened file location.")
        except Exception as e: self.show_temporary_status(f"Could not open file: {e}",3000)
    def search_process_online(self,p): webbrowser.open(f"https://www.google.com/search?q={p}+process"); self.show_temporary_status(f"Searching for '{p}'...")
    def closeEvent(self,e): self.db_conn and self.db_conn.close(); self.settings.setValue("geometry",self.saveGeometry()); self.worker.stop(); e.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())