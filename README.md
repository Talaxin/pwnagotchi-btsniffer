# pwnagotchi-btsniffer
pwnagotchi bluetooth device sniffer and wigle.net csv maker and uploader

## Ethical Use Notice
This project is provided for educational, research, and personal lawful use only.

Do not use this software for any activity that violates privacy, breaks local laws, or harms networks or devices you do not own or have permission to test.

You are responsible for obeying all applicable laws. The author(s) assume no liability for misuse.


## CONFIG.TOML

### Enable Plugin
main.plugins.bluetoothsniffer.enabled = true

### Scan controls
main.plugins.bluetoothsniffer.timer = 45                      # Seconds between each BT scan
main.plugins.bluetoothsniffer.scan_duration = 10              # How long each scan runs (sec)
main.plugins.bluetoothsniffer.file_size = 15000               # CSV rollover size in bytes (15KB default)

### Files & logging
main.plugins.bluetoothsniffer.devices_file = "/root/handshakes/bluetooth_devices.csv"  # Live BT capture log file

### UI placement on screen
main.plugins.bluetoothsniffer.bt_x_coord = 160
main.plugins.bluetoothsniffer.bt_y_coord = 66

### GPS configuration
main.plugins.bluetoothsniffer.gps_host = "127.0.0.1"          # GPSD host
main.plugins.bluetoothsniffer.gps_port = 2947                 # GPSD port

### Ignore known devices (do not log or upload these MACs)
main.plugins.bluetoothsniffer.blacklist = [
 "AA:BB:CC:DD:EE:FF",
 "11:22:33:44:55:66",
]

### Upload settings
main.plugins.bluetoothsniffer.path = "/root/handshakes/toupload"   # Folder where finished CSVs go
main.plugins.bluetoothsniffer.wigle_name = ""                      # Your WiGLE username
main.plugins.bluetoothsniffer.wigle_api_token = ""                 # WiGLE API token
main.plugins.bluetoothsniffer.remove_on_success = true             # Delete CSV after successful upload
