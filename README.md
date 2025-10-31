# pwnagotchi-btsniffer
pwnagotchi bluetooth device sniffer and wigle.net csv maker and uploader

## Ethical Use Notice
This project is provided for educational, research, and personal lawful use only.

Do not use this software for any activity that violates privacy, breaks local laws, or harms networks or devices you do not own or have explicit permission to test.

You are responsible for obeying all applicable laws. The author(s) assume no liability for misuse.



## Custom plugin repository

Edit your /etc/pwnagotchi/config.toml to look like this:
```
main.custom_plugin_repos = [
    "https://github.com/Talaxin/pwnagotchi-btsniffer/archive/master.zip",
]
```
Then run this command:
```
sudo pwnagotchi plugins update
```
## Install Bluetooth Sniffer Plugin
```
sudo pwnagotchi plugins install btsniffer
```
Add the following to /etc/pwnagotchi/config.toml
```toml
# Enable Plugin
main.plugins.btsniffer.enabled = true

# Scan controls
main.plugins.btsniffer.timer = 45
main.plugins.btsniffer.scan_duration = 10
main.plugins.btsniffer.file_size = 15000 #bytes

# Files & logging
main.plugins.btsniffer.devices_file = "/root/handshakes/bluetooth_devices.csv"

# UI placement on screen
main.plugins.btsniffer.bt_x_coord = 160
main.plugins.btsniffer.bt_y_coord = 66

# GPS configuration
main.plugins.btsniffer.gps_host = "127.0.0.1"
main.plugins.btsniffer.gps_port = 2947

# Ignore known devices (do not log these MACs)
main.plugins.btsniffer.blacklist = [
 "AA:BB:CC:DD:EE:FF",
 "11:22:33:44:55:66",
]

# Upload settings
main.plugins.btsniffer.path = "/root/handshakes/toupload"
main.plugins.btsniffer.wigle_name = ""
main.plugins.btsniffer.wigle_api_token = ""
main.plugins.btsniffer.remove_on_success = true
```
## Finally restart pwnagotchi
```
sudo systemctl restart pwnagotchi
