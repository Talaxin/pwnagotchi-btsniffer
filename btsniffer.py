#!/usr/bin/env python3

import logging
import os
import subprocess
import json
import time
import shutil
import csv
import socket
import threading
from datetime import datetime
from typing import List

import requests
import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK


class btsniffer(plugins.Plugin):
    """
    Combined btsniffer + CSV-only HandshakeUploader (uploads .csv files).
    GPSD Required. Produces WiGLE CSV compatible output.
    """

    __author__ = 'diytechtinker, fixed by Jayofelony, updated and enhanced by Talaxin'
    __version__ = '0.5.2'
    __license__ = 'GPL3'
    __description__ = ('Sniffs Bluetooth devices, logs WiGLE-compatible CSV with GPSD '
                       'support and a CSV-only uploader integrated (uploads when internet available).')

    def __init__(self):
        # btsniffer options
        self.options = {
            'timer': 45,  # Time to wait between scans
            'scan_duration': 10,  # How long to scan for, should be higher in dense areas/traveling fast
            'devices_file': '/root/handshakes/bluetooth_devices.csv',  # Where to store and what to call the bt-device csv file
            'file_size': 15000,  # 15KB, How large to make the file before uploading. larger file = longer upload intervals
            'bt_x_coord': 160,
            'bt_y_coord': 66,
            'gps_host': '127.0.0.1',
            'gps_port': 2947,
            'upload_check_interval': 300,  # Check for uploads every 5 minutes
            'blacklist': [
                "AA:BB:CC:DD:EE:FF",  # Ignore these BT mac addrs
                "11:22:33:44:55:66",
            ]
        }

        # HandshakeUploader options
        self.uploader_options = {
            'path': '/root/handshakes/toupload/',  # Where to upload files from
            'uploaded_path': '/root/handshakes/uploaded/',  # Where to move files after successful upload
            'remove_on_success': True,  # Should it delete the file after uploaded to wigle (from uploaded_path)
            'wigle_name': '',  # Wigle username
            'wigle_api_token': '',  # Wigle API token
        }

        self.data = {}
        self.last_scan_time = 0
        self._last_upload_check = 0
        self._uploader_lock = threading.Lock()
        self._uploading = False

    # ---------------- lifecycle ----------------
    def on_loaded(self):
        logging.info("[BT-Sniffer] btsniffer plugin loading...")

        try:
            cfg_blacklist = self.options.get('blacklist', [])
            self.options['blacklist'] = [m.upper() for m in cfg_blacklist]
        except Exception:
            self.options['blacklist'] = []

        # Load WiGLE credentials from config into uploader_options
        self.uploader_options['wigle_name'] = self.options.get('wigle_name', '')
        self.uploader_options['wigle_api_token'] = self.options.get('wigle_api_token', '')
        self.uploader_options['remove_on_success'] = self.options.get('remove_on_success', True)
        self.uploader_options['uploaded_path'] = self.options.get('uploaded_path', '/root/handshakes/uploaded/')

        # Ensure directories
        os.makedirs(
            os.path.dirname(self.options['devices_file']),
            exist_ok=True
        )
        os.makedirs(self.uploader_options['path'], exist_ok=True)
        os.makedirs(self.uploader_options['uploaded_path'], exist_ok=True)

        if not os.path.exists(self.options['devices_file']):
            self.write_csv_header()
        else:
            # Load already-logged devices from existing CSV to prevent duplicates
            self._load_existing_devices()

        logging.info(f"[BT-Sniffer] Output CSV: {self.options['devices_file']}")
        logging.info(f"[BT-Sniffer] Blacklist: {', '.join(self.options['blacklist']) or '(none)'}")
        logging.info(f"[BT-Sniffer] Already tracking {len(self.data)} device(s) from existing CSV")

        # Log if WiGLE credentials are configured
        if self.uploader_options['wigle_name'] and self.uploader_options['wigle_api_token']:
            logging.info(f"[BT-Sniffer] WiGLE API configured for user: {self.uploader_options['wigle_name']}")
        else:
            logging.warning("[BT-Sniffer] WiGLE credentials not configured - uploads will be skipped")

    def on_ui_setup(self, ui):
        with ui._lock:
            ui.add_element('BT-Sniffer', LabeledValue(
                color=BLACK,
                label='BT SNFD',
                value=" ",
                position=(int(self.options["bt_x_coord"]), int(self.options["bt_y_coord"])),
                label_font=fonts.Small,
                text_font=fonts.Small
            ))

    def on_ui_update(self, ui):
        now = time.time()
        
        # Regular scanning
        if now - self.last_scan_time >= int(self.options.get('timer', 45)):
            self.last_scan_time = now
            ui.set('BT-Sniffer', str(self.bt_sniff_info()))
            try:
                self.scan(ui)
            except Exception as e:
                logging.exception(f"[BT-Sniffer] Exception during scan: {e}")
        
        # Periodic upload check - NEW!
        upload_interval = int(self.options.get('upload_check_interval', 300))
        if now - self._last_upload_check >= upload_interval:
            self._last_upload_check = now
            pending_files = self._list_csv_files()
            if pending_files:
                logging.info(f"[BT-Sniffer] Periodic check: {len(pending_files)} file(s) pending upload")
                if self._check_internet():
                    logging.info("[BT-Sniffer] Internet available, triggering upload...")
                    t = threading.Thread(target=self._upload_all, daemon=True)
                    t.start()
                else:
                    logging.debug("[BT-Sniffer] No internet connection, will retry later")

    # ---------------- CSV Header ----------------
    def write_csv_header(self):
        pre_header = (
            "WigleWifi-1.6,appRelease=1.0,model=RaspberryPi,release=jayofelony,"
            "device=RaspberryPi,display=display,board=board,"
            "brand=RaspberryPi,star=Sol,body=3,subBody=0\n"
        )
        header = [
            'MAC', 'SSID', 'AuthMode', 'FirstSeen', 'Channel', 'Frequency',
            'RSSI', 'CurrentLatitude', 'CurrentLongitude', 'AltitudeMeters',
            'AccuracyMeters', 'RCOIs', 'MfgrId', 'Type'
        ]
        try:
            with open(self.options['devices_file'], 'w', newline='') as csvfile:
                csvfile.write(pre_header)
                writer = csv.writer(csvfile)
                writer.writerow(header)
        except Exception as e:
            logging.error(f"[BT-Sniffer] Unable to write CSV header: {e}")

    def _load_existing_devices(self):
        """Load MAC addresses from existing CSV file to prevent duplicate logging"""
        file_path = self.options['devices_file']
        try:
            with open(file_path, 'r', newline='') as csvfile:
                # Read first line to check for pre-header
                first_line = csvfile.readline()
                csvfile.seek(0)  # Reset to beginning
                
                reader = csv.reader(csvfile)
                
                # Skip pre-header line if present (WigleWifi-1.6...)
                if first_line.startswith('WigleWifi'):
                    next(reader, None)
                
                # Skip header row (MAC, SSID, etc.)
                header = next(reader, None)
                if not header or header[0] != 'MAC':
                    # No valid header found, can't parse
                    return
                
                # Read all data rows and extract MAC addresses
                for row in reader:
                    if len(row) > 0:
                        mac = row[0].strip().upper()
                        if mac and mac != 'MAC':  # Skip header if present
                            # Store with first_seen from CSV if available
                            if mac not in self.data:
                                first_seen = row[3] if len(row) > 3 else datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                                self.data[mac] = {'first_seen': first_seen}
        except Exception as e:
            logging.warning(f"[BT-Sniffer] Could not load existing devices from CSV: {e}")
            # If we can't read the file, start fresh
            self.data = {}

    # ---------------- GPSD ----------------
    def get_gps_coords(self):
        try:
            host = self.options.get('gps_host', '127.0.0.1')
            port = int(self.options.get('gps_port', 2947))
            gps_data = None

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                s.connect((host, port))
                s.sendall(b'?WATCH={"enable":true,"json":true}\n')

                buf = ""
                end = time.time() + 2.5
                while time.time() < end:
                    chunk = s.recv(4096).decode('utf-8', errors='ignore')
                    if not chunk:
                        break
                    buf += chunk

                    while '\n' in buf:
                        line, buf = buf.split('\n', 1)
                        try:
                            obj = json.loads(line)
                            if obj.get('class') == 'TPV':
                                gps_data = obj
                                raise StopIteration
                        except StopIteration:
                            raise
                        except Exception:
                            continue
        except StopIteration:
            pass
        except Exception:
            gps_data = None

        if gps_data:
            lat = float(gps_data.get('lat', 0.0) or 0.0)
            lon = float(gps_data.get('lon', 0.0) or 0.0)
            alt = float(gps_data.get('altMSL', gps_data.get('alt', 0.0) or 0.0))
            acc = float(gps_data.get('epx', gps_data.get('eps', 0.0) or 0.0))
            return lat, lon, alt, acc

        return 0.0, 0.0, 0.0, 0.0

    # ---------------- Bluetooth Scan ----------------
    def scan(self, display):
        scan_duration = int(self.options.get('scan_duration', 10))
        logging.info(f"[BT-Sniffer] Starting bluetoothctl scan for {scan_duration}s")

        lat, lon, alt, acc = self.get_gps_coords()
        scan_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        try:
            subprocess.run("bluetoothctl scan on &", shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(scan_duration)
            subprocess.run("bluetoothctl scan off", shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logging.debug(f"[BT-Sniffer] Error controlling bluetoothctl: {e}")

        try:
            output = subprocess.check_output(
                "bluetoothctl devices", shell=True
            ).decode(errors='ignore')
        except subprocess.CalledProcessError:
            output = ""

        if not output:
            self.check_rollover()
            display.update(force=True)
            return

        rows_written = 0
        for line in output.strip().splitlines():
            if "Device " not in line:
                continue

            parts = line.strip().split(" ", 2)
            if len(parts) < 2:
                continue

            mac = parts[1].upper()
            name = parts[2].strip() if len(parts) > 2 else ""

            # Skip blacklisted devices
            if mac in self.options['blacklist']:
                continue

            # Skip if we've already logged this MAC before
            if mac in self.data:
                continue

            # Mark device as seen
            self.data[mac] = {'first_seen': scan_time}

            # Fetch info
            mfgr = self.get_device_manufacturer(mac)
            rssi = self.get_device_rssi(mac)
            devtype = self.get_device_type(mac)

            try:
                with open(self.options['devices_file'], 'a', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([
                        mac,
                        name,
                        f"Misc [{devtype}]",
                        self.data[mac]['first_seen'],
                        0,
                        0,
                        rssi,
                        f"{lat:.9f}",
                        f"{lon:.9f}",
                        f"{alt:.1f}",
                        f"{acc:.6f}",
                        '',
                        mfgr,
                        devtype
                    ])
                    rows_written += 1
            except Exception as e:
                logging.error(f"[BT-Sniffer] Error writing row {mac}: {e}")

        if rows_written:
            logging.info(f"[BT-Sniffer] Wrote {rows_written} rows.")
            display.set('status', 'Bluetooth sniffed + stored')

        self.check_rollover()
        display.update(force=True)

    # ---------------- Info helpers ----------------
    def get_device_manufacturer(self, mac):
        try:
            out = subprocess.check_output(f"bluetoothctl info {mac}", shell=True).decode()
            for line in out.splitlines():
                if "Manufacturer" in line:
                    return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return ''

    def get_device_rssi(self, mac):
        try:
            out = subprocess.check_output(f"bluetoothctl info {mac}", shell=True).decode()
            for line in out.splitlines():
                if "RSSI" in line:
                    return int(line.split(":", 1)[1].strip())
        except Exception:
            pass
        return 0

    def get_device_type(self, mac):
        try:
            out = subprocess.check_output(f"bluetoothctl info {mac}", shell=True).decode()
            for line in out.splitlines():
                if "Type" in line:
                    dtype = line.split(":", 1)[1].strip()
                    if "LE" in dtype:
                        return "BLE"
        except Exception:
            pass
        return "BT"

    # ---------------- Rollover ----------------
    def check_rollover(self):
        file_path = self.options['devices_file']
        size_limit = self.options.get('file_size', 15000)
        upload_dir = self.uploader_options['path']

        try:
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir, exist_ok=True)

            if os.path.exists(file_path) and os.path.getsize(file_path) >= size_limit:
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                base_name = os.path.basename(file_path).replace('.csv', f'_{ts}.csv')
                dest_path = os.path.join(upload_dir, base_name)

                shutil.move(file_path, dest_path)
                logging.info(f"[BT-Sniffer] Rolled over -> {dest_path}")

                # Recreate CSV header for the new active file
                self.write_csv_header()
                self.data.clear()
        except Exception as e:
            logging.error(f"[BT-Sniffer] Rollover error: {e}")

    # ---------------- Internet Check ----------------
    def _check_internet(self):
        """Quick check if internet is available"""
        try:
            response = requests.get('https://api.wigle.net', timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    # ---------------- Uploader ----------------
    def _list_csv_files(self):
        path = self.uploader_options['path']
        try:
            files = [os.path.join(path, f) for f in os.listdir(path)
                    if f.lower().endswith('.csv') and os.path.isfile(os.path.join(path, f))]
            files.sort(key=lambda f: os.path.getmtime(f))
            return files
        except Exception:
            return []

    def _upload_file(self, file_path):
        """
        Upload CSV file to WiGLE using Basic Auth (same method Wardriver uses).
        """
        url = "https://api.wigle.net/api/v2/file/upload"
        username = self.uploader_options.get('wigle_name')
        token = self.uploader_options.get('wigle_api_token')

        if not username or not token:
            logging.warning(f"[BT-Sniffer] Missing WiGLE credentials for upload, skipping {file_path}.")
            return False

        try:
            auth = (username, token)
            logging.info(f"[BT-Sniffer] Uploading {file_path} to WiGLE...")

            with open(file_path, "rb") as fp:
                files = {"file": fp}
                response = requests.post(url, files=files, auth=auth, timeout=120)

            if response.status_code == 200:
                try:
                    resp_json = response.json()
                    if resp_json.get("success"):
                        logging.info(f"[BT-Sniffer] WiGLE upload successful: {file_path}")
                        
                        # Move file to uploaded directory
                        uploaded_dir = self.uploader_options.get('uploaded_path', '/root/handshakes/uploaded/')
                        os.makedirs(uploaded_dir, exist_ok=True)
                        file_name = os.path.basename(file_path)
                        uploaded_file_path = os.path.join(uploaded_dir, file_name)
                        
                        try:
                            shutil.move(file_path, uploaded_file_path)
                            logging.info(f"[BT-Sniffer] Moved uploaded file to: {uploaded_file_path}")
                            
                            # Delete from uploaded directory if remove_on_success is True
                            if self.uploader_options.get('remove_on_success', True):
                                os.remove(uploaded_file_path)
                                logging.info(f"[BT-Sniffer] Deleted uploaded file: {uploaded_file_path}")
                        except Exception as move_error:
                            logging.error(f"[BT-Sniffer] Error moving file to uploaded directory: {move_error}")
                        
                        return True
                    else:
                        logging.warning(f"[BT-Sniffer] WiGLE upload failed: {resp_json}")
                except Exception:
                    logging.warning(f"[BT-Sniffer] WiGLE returned non-JSON success: {response.text}")
            else:
                logging.error(f"[BT-Sniffer] WiGLE upload HTTP {response.status_code}: {response.text}")

        except Exception as e:
            logging.error(f"[BT-Sniffer] WiGLE upload exception: {e}")

        return False

    def _upload_all(self):
        if self._uploader_lock.locked():
            logging.debug("[BT-Sniffer] Upload already in progress, skipping")
            return

        with self._uploader_lock:
            files = self._list_csv_files()
            if not files:
                logging.debug("[BT-Sniffer] No files to upload")
                return

            logging.info(f"[BT-Sniffer] Starting upload of {len(files)} file(s)...")
            for f in files:
                self._upload_file(f)
                time.sleep(1)
            logging.info("[BT-Sniffer] Upload batch complete")

    def on_internet_available(self, agent):
        """Called by Pwnagotchi when internet becomes available"""
        logging.info("[BT-Sniffer] Internet detected (on_internet_available), uploading files...")
        t = threading.Thread(target=self._upload_all, daemon=True)
        t.start()

    def bt_sniff_info(self):
        return str(len(self.data))


PLUGIN = btsniffer()
