# TelHound - A Network Telemetry Monitor

TelHound is a Windows desktop application that monitors active network connections in real-time, identifies potential telemetry or tracking endpoints, and provides tools to investigate and block them.

![Screenshot of TelHound](assets\demo.png) 

## Features

*   **Live Connection Monitoring:** See all established TCP connections from your machine.
*   **Suspicious Connection Highlighting:** Automatically flags connections to known telemetry domains (Microsoft, Google, etc.) using a customizable blocklist.
*   **Whois Information:** Fetches the owner of the remote IP address to identify the organization behind the connection.
*   **Persistent History:** Logs all connections to a local SQLite database for later review.
*   **Firewall Integration:** (If run as Admin) Instantly create Windows Firewall rules to block suspicious connections.
*   **Context Menu Tools:** Easily copy IP/Hostname, look up a process online, or open its file location.

## How to Run

1.  Download the latest `.exe` from the [Releases page](link_to_your_releases_page).
2.  Ensure `blocklist.txt` is in the same directory as the `.exe`.
3.  Run the `.exe`. For full functionality (like blocking connections), right-click and "Run as administrator".

## How to Build from Source

1.  Clone this repository.
2.  Install dependencies: `pip install -r requirements.txt`
3.  Place `icon.ico` in the root directory.
4.  Build the executable using PyInstaller:
    ```bash
    pyinstaller --noconsole --onefile --icon="icon.ico" --add-data "icon.ico;." telhound_v1.7.py
    ```

## Dependencies

*   PySide6
*   psutil
*   ipwhois