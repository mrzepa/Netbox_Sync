# Firewall and Aruba Central to Netbox Sync Script

This project allows the synchronization of firewalls managed by Panorama with NetBox, and APs and Switches managed by Aruba Central with NetBox. It ensures that devices, interfaces, management IPs, and other metadata are correctly added or updated between the two systems.

---

## Prerequisites

1. Python 3.12 or higher (ensure it's installed on your system).
2. Required packages are installed. Install them by running:
   ```bash
   pip install -r requirements.txt
   ```
3. `.env` file containing API credentials.
4. `firewalls.yaml` for firewall-specific configurations.
5. `netbox.yaml` for NetBox-related configurations.

---

## `.env` File Instructions

The `.env` file contains sensitive configuration details such as API tokens and Panorama credentials. This file must be created in the root directory of the project.

### Example `.env` File:
```ini
# Panorama connection details
PANORAMA_IP=<your_panorama_ip>
PANORAMA_API_KEY=<your_panorama_api_key>
PANO_USERNAME=<your username for connecting to firewalls>
PANO_PASSWORD=<your password for connecting to firewalls>

# NetBox connection details
NETBOX_API_TOKEN=<your_netbox_api_token>

# General details
INPUT_DIR=<directory with yaml files>

# Aruba Central details
ARUBA_CENTRAL_USERNAME=<username>
ARUBA_CENTRAL_PASSWORD=<password>
ARUBA_CENTRAL_CLIENT_ID=<client id>
ARUBA_CENTRAL_CLIENT_SECRET=<client secret>
ARUBA_CENTRAL_CUSTOMER_ID=<customer id>
ARUBA_CENTRAL_BASE_URL=<your aruba central url>
```

---

## `firewalls.yaml` Instructions

The `firewalls.yaml` file contains firewall-specific configurations, such as firewall names to skip and interfaces to exclude from processing. It must be created in the <INPUT_DIR> directory.

### Example `firewalls.yaml`:
```yaml
names_to_skip:
  - azure-firewall-01
  - azure-firewall-02

interfaces_to_skip:
  - loopback0
  - loopback1
```

### Explanation:
- `names_to_skip`: A list of firewall hostnames that should be excluded from syncing.
- `interfaces_to_skip`: A list of interface names that should not be processed (e.g., loopback interfaces).

---

## `netbox.yaml` Instructions

The `netbox.yaml` file contains NetBox-related information, including mapping firewall roles and other metadata. It must be created in the <INPUT_DIR> directory.

### Example `netbox.yaml`:
```yaml
roles:
  firewall: Firewall
url: <base url for netbox>
tenant: <Netbox tenent to assign the new devices being created>
vrf: <Netbox vrf to assign the new ip addresses being created>
```

---

## Running the Script

After setting up the necessary files:

1. Ensure the Python environment is properly configured.
2. Execute the script:
   ```bash
   python main.py
   ```

---

## Notes

1. **Security**:
   - Do not hardcode sensitive credentials in the code.
   - Ensure `.env`, `firewalls.yaml`, and `netbox.yaml` are included in `.gitignore` to prevent exposing them in version control.

2. **Logging**:
   - Logs will provide detailed insights into processing firewalls, adding devices, or handling IP mismatches.

3. **Customization**:
   - You can update `firewalls.yaml` and `netbox.yaml` based on your environment and specific requirements.

---

## Author
Mark Rzepa
mark@rzepa.com