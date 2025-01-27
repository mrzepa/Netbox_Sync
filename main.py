import os
import time
import sys
from pycentral.base import ArubaCentralBase
from pycentral.monitoring import Sites
import logging
from dotenv import load_dotenv
from datetime import datetime
import pynetbox
import yaml
from icecream import ic
from pypanrestv2.Base import Panorama, Firewall
from pypanrestv2.Network import EthernetInterfaces, TunnelInterfaces, VLANInterfaces, AggregateEthernetInterfaces
import ipaddress
import warnings
import concurrent.futures
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

def add_ip_to_interface(ip_entry: dict, nb: pynetbox.api, interface_name: str, hostname: str, serial: str, nb_intf:pynetbox) -> bool:
    """
    Add an IP address to a specified interface in NetBox.

    This function checks if an IP address is valid using the ipaddress module.
    If it is valid, it ensures the IP address is associated with the given
    interface in NetBox. If no IP address is found on the interface in NetBox,
    it creates and assigns a new IP address to the interface. Logging is used
    to handle warnings, errors, and informational messages throughout the process.

    :param nb_intf: Netbox interface object
    :param ip_entry: A dict representing an IP addresss, extracted from the provided
        input. It must conform to a valid IP address format as per the ipaddress module.
    :param nb: An instance of the pynetbox.api class that interacts with
        the NetBox API to manage IP addresses and interfaces.
    :param interface_name: The name of the network interface to which the IP
        address should be added in NetBox.
    :param hostname: The hostname of the device where the interface is located.
    :param serial: The serial number of the device where the interface is located.
    :return: A boolean value. It returns True if the IP address was successfully
        added or already exists on the specified interface in NetBox.
    """
    for ip in ip_entry:
        ip_addr = ip['@name']
        try:
            ipaddress.ip_interface(ip_addr)
        except ValueError:
            logger.warning(f'{ip_addr} is not a valid IP address, skipping')
            return False
        # Check to see if the IP address is in netbox and associated with the interface
        nb_ip = nb.ipam.ip_addresses.get(interface_id=nb_intf.id)
        if not nb_ip:
            logger.info(f'No IP on interface {interface_name} for {hostname}, {serial} in Netbox. Adding it now.')
            new_addr = nb.ipam.ip_addresses.create(address=f'{ip_addr}',
                                                   vrf_id=vrf.id,
                                                   tenant_id=tenant.id,
                                                   status='active',
                                                   assigned_object_type='dcim.interface',
                                                   assigned_object_id=nb_intf.id,
                                                   )
            if new_addr:
                logger.info(f'Added {interface_name} IP {ip_addr} with ID: {new_addr.id} for {hostname}, {serial} to Netbox.')
            else:
                logger.error(
                    f'Failed to add {interface_name} IP {ip_addr} for {hostname}, {serial} to Netbox.')
        else:
            # Check if the IP in NetBox matches the one reported by the firewall
            if nb_ip.address != ip_addr:
                logger.warning(
                    f'IP mismatch on {interface_name} for {hostname}, {serial}. '
                    f'NetBox has {nb_ip.address}, but the firewall reports {ip_addr}. Updating NetBox.'
                )
                try:
                    # Update the IP address in NetBox
                    nb_ip.update({'address': ip_addr})
                    logger.info(f'Updated IP {ip_addr} on {interface_name} for {hostname}, {serial} in NetBox.')
                except pynetbox.core.query.RequestError as e:
                    logger.error(f'Failed to update IP for {interface_name} on {hostname}, {serial}. Error: {e}')
    return True

def find_site_for_ip(ip_address):
    """
    Finds the associated site for a given IP address by first determining the /24 prefix
    and then querying the prefix in NetBox. If no prefix or associated site is found,
    appropriate logging is performed, and a corresponding value is returned. Handles
    potential errors such as invalid IP formats or query failures.

    :param ip_address: The input IP address (IPv4 or IPv6) for which the associated site needs to be found.
    :type ip_address: str
    :return: The site associated with the /24 prefix of the given IP address if found,
        otherwise None. If the IP address is invalid, a descriptive error string is returned.
    :rtype: Union[str, object]
    :raises ValueError: Raised if the provided IP address is invalid.
    :raises pynetbox.core.query.RequestError: Raised if there is an error during the NetBox query.
    """
    # Step 1: Calculate the /24 prefix for the given IP
    try:
        ip_obj = ipaddress.ip_interface(ip_address)  # Create an ipaddress object
        ip_prefix = ip_obj.network.supernet(new_prefix=24)
    except ValueError as e:
        return f"Invalid IP address: {e}"

    # Step 2: search for the prefix in Netbox
    try:
        prefix = nb.ipam.prefixes.get(prefix=str(ip_prefix))  # Lookup the /24 prefix
        if not prefix:
            logger.error(f"No prefix found in NetBox for {ip_prefix}")
            return None

        # Step 3: Retrieve the associated site for the prefix
        if prefix.site:
            return prefix.site
        else:
            logger.error(f"No site associated with prefix {ip_prefix} in NetBox")
            return None
    except pynetbox.core.query.RequestError as e:
        logger.exception(f"Failed to retrieve site for prefix {ip_prefix}: {e}")
        return None

def process_firewall(item, pano_api_key, nb, firewall_data, logger, netbox_data, tenant):
    """
    Function to process a single firewall. Contains the logic for handling
    devices, interfaces, and management IP synchronization.
    """
    hostname = item['hostname']
    # Skip the azure firewalls
    for azure_firewall in firewall_data['names_to_skip']:
        if azure_firewall in hostname:
            return

    model = item['model']
    ip_address = item['ip_address']
    serial = item['serial']

    # See if the device already exists in NetBox, if not, add it.
    try:
        nb_device = nb.dcim.devices.get(serial=serial)
    except ValueError:
        nb_devices = nb.dcim.devices.filter(serial=serial)
        for i in nb_devices:
            logger.warning(f"Duplicate serial {serial} found for firewall {hostname}, device {i.name} with ID {i.id}")
        return

    if not nb_device:
        logger.warning(
            f"No device found for serial {serial}, hostname {hostname}, {ip_address} in NetBox. Adding it now.")
        nb_device_type = nb.dcim.device_types.get(model=model)
        nb_device_role = nb.dcim.device_roles.get(name=netbox_data['roles']['firewall'])
        site = find_site_for_ip(ip_address)
        nb_device = nb.dcim.devices.create(
            name=hostname,
            serial=serial,
            device_type=nb_device_type.id,
            device_role=nb_device_role.id,
            site=site.id,
            status="active",
            tenant_id=tenant.id,
        )
        if nb_device:
            logger.info(f"Successfully added device {hostname} with ID: {nb_device.id} to NetBox.")
        else:
            logger.error(f"Failed to add device {hostname} to NetBox.")
            return

    # Retrieve firewall interfaces and process them
    try:
        fw = Firewall(ip_address, api_key=pano_api_key)
        ethernet_interfaces = EthernetInterfaces(fw, location="panorama-pushed")
        vlan_interfaces = VLANInterfaces(fw, location="panorama-pushed")
        tunnel_interfaces = TunnelInterfaces(fw, location="panorama-pushed")
    except requests.exceptions.ConnectTimeout:
        logger.warning(f"Cannot connect to firewall {ip_address} with serial {serial}, skipping...")
        return

    interface_list = []
    for interfaces in [ethernet_interfaces.get(), vlan_interfaces.get(), tunnel_interfaces.get()]:
        if interfaces:
            interface_list.extend(interfaces)

    for interface in interface_list:
        interface_name = interface["@name"]
        if interface_name in firewall_data["interfaces_to_skip"]:
            continue

        try:
            if interface.get("layer3"):
                nb_intf = nb.dcim.interfaces.get(name=interface_name, device_id=nb_device.id)
                if not nb_intf:
                    logger.error(f"No interface found for {hostname}, {serial}, {interface_name}. Skipping...")
                    continue
                if interface["layer3"].get("ip"):
                    ip_entry = interface["layer3"]["ip"]["entry"]
                    if not add_ip_to_interface(ip_entry, nb, interface_name, hostname, serial, nb_intf):
                        continue
            elif interface.get("ip"):
                nb_intf = nb.dcim.interfaces.get(name=interface_name, device_id=nb_device.id)
                if not nb_intf:
                    nb_intf = nb.dcim.interfaces.create(name=interface_name, device=nb_device.id, type="virtual")
                ip_entry = interface["ip"]["entry"]
                if not add_ip_to_interface(ip_entry, nb, interface_name, hostname, serial, nb_intf):
                    continue
        except IndexError as e:
            logger.exception(f"Failed to get IP address for {hostname}, {serial}, {interface_name}: {e}")
            continue

    # Add or update the management IP info
    mgmt_intf = nb.dcim.interfaces.get(name="management", device_id=nb_device.id)
    if not mgmt_intf:
        logger.warning(f"No management interface found for {hostname}, {serial}")
        return
    mgmt_ip = nb.ipam.ip_addresses.get(interface_id=mgmt_intf.id)
    if not mgmt_ip:
        logger.debug(f"No management IP for {hostname}, {serial}")
        new_addr = nb.ipam.ip_addresses.create(
            address=f"{ip_address}/24",
            vrf_id=vrf.id,
            tenant_id=tenant.id,
            status="active",
            assigned_object_type="dcim.interface",
            assigned_object_id=mgmt_intf.id,
        )
        if new_addr:
            logger.info(f"Added management IP {ip_address} for {hostname}, {serial} with ID: {new_addr.id} to NetBox.")
        else:
            logger.error(f"Failed to add management IP {ip_address} for {hostname}, {serial} to NetBox.")
    else:
        if str(ipaddress.ip_interface(mgmt_ip.address).ip) != str(ipaddress.ip_interface(ip_address).ip):
            logger.warning(
                f"IP mismatch on management interface for {hostname}, {serial}. "
                f"NetBox has {mgmt_ip.address}, but the firewall reports {ip_address}. Updating NetBox."
            )
            try:
                mgmt_ip.update({"address": f"{ip_address}/24"})
                logger.info(f"Updated IP {ip_address} on management interface for {hostname}, {serial} in NetBox.")
            except pynetbox.core.query.RequestError as e:
                logger.error(f"Failed to update IP for management interface on {hostname}, {serial}. Error: {e}")


def firewall_sync(panorama_ip, pano_api_key):
    # Connect to Panorama
    pano = Panorama(panorama_ip, api_key=pano_api_key)

    # Get a list of all the firewalls connected to Panorama
    firewall_list = pano.get_firewall_connected()

    # Run the firewall processing loop in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [
            executor.submit(process_firewall, item, pano_api_key, nb, firewall_data, logger, netbox_data, tenant)
            for item in firewall_list
        ]
        # Optional: Wait for all threads to complete
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error processing firewall: {e}")


def sync_ac(path: str, device: str, role: str):
    """
    Fetches data from an API endpoint, processes the retrieved information, and updates the NetBox inventory
    as required. The function retrieves a device list from the given endpoint in paginated requests. It validates
    the data, compares it with NetBox's existing entries, and either adds new devices or updates existing ones.

    :param path: The API endpoint path used to fetch data.
    :type path: str
    :param device: The type of the device being fetched, such as 'switches' or other device categories.
    :type device: str
    :param role: The device role in NetBox, used for matching or creating devices under a specific role.
    :type role: str
    :return: None
    :rtype: None
    """
    page = 0
    limit = 100
    device_list = []

    while True:
        params = {'offset': page, 'limit': limit}
        try:
            result = ac.command(apiMethod='GET', apiParams=params, apiPath=path)
        except Exception as e:
            logger.error(f"Failed to fetch data from API at offset {page}: {e}")
            break

        # Validate the result structure
        if result.get('code') != 200 or 'msg' not in result or device not in result['msg']:
            logger.error(f"Unexpected API response at offset {page}: {result}")
            break

        # Extend the device list with the fetched results
        device_list.extend(result['msg'][device])

        # Check if we have reached the end
        if len(result['msg'][device]) < limit:
            break

        # Increment the page offset
        page += limit

    # Go through the list, and compare to Netbox, update as needed
    if device_list:
        for item in device_list:
            model = item['model']
            name = item['name']
            serial = item['serial']
            site = item['site']
            if device == 'switches':
                if item['stack_id']:
                    name = f'{name} - stack member {item["serial"]}'
            try:
                nb_device = nb.dcim.devices.get(serial=serial)
            except ValueError as e:
                logger.warning(f'Duplicate serial found: {serial}')
                duplicate_report = nb.dcim.devices.filter(serial=serial)
                for i in duplicate_report:
                    logger.warning(f'Duplicate serial found: {serial} in Netbox, device {i.name} with ID {i.id}')
                continue
            if not nb_device:
                # Device does not exist in netbox, so we need to add it.
                device_type = nb.dcim.device_types.get(model=model)
                if not device_type:
                    # search for the custom field cf_ArubaCentralModel
                    device_type = nb.dcim.device_types.get(cf_ArubaCentralModel=model)
                    if not device_type:
                        # search for model based on the part number:
                        try:
                            part_number = model.split('(')[1].split(')')[0]
                            device_type = nb.dcim.device_types.get(part_number=part_number)
                            if not device_type:
                                logger.warning(f'Device type {model} not found in Netbox, skipping...')
                                continue
                        except IndexError:
                            logger.warning(f'Device type {model} not found in Netbox, skipping...')
                            continue

                device_role = nb.dcim.device_roles.get(name=role)
                if not device_role:
                    logger.warning(f'Device role "{role}" not found in Netbox, skipping...')
                    continue
                nb_site = nb.dcim.sites.get(name=site)
                if not nb_site:
                    logger.warning(f'Site "{site}" not found in Netbox, skipping...')
                    continue
                try:
                    nb_device = nb.dcim.devices.create(name=name,
                                                       device_type=device_type.id,
                                                       device_role=device_role.id,
                                                       site=nb_site.id,
                                                       status='active',
                                                       serial=serial,
                                                       tenant_id=tenant.id)
                    if nb_device:
                        logger.info(f'Succesfully added device {name} with ID: {nb_device.id} to Netbox.')
                    else:
                        logger.error(f'Failed to add device {name} to Netbox.')
                except pynetbox.core.query.RequestError as e:
                    logger.exception(f'Could not add device {name} to Netbox: {e}')
            else:
                # the device exists in netbox, lets see if it's name has changed
                if nb_device.name != name:
                    logger.info(
                        f'Device with serial number {serial} and name {name} already exists in Netbox with name {nb_device.name}. Updating name..., ')
                    nb_device.name = name
                    nb_device.save()
                    logger.info(
                        f'Device with serial number {serial} and name {name} updated in Netbox with ID {nb_device.id} with name {nb_device.name}.')

def aruba_switch_sync(ac):
    """
    Synchronizes switch data from Aruba switches using the specified Aruba Central (AC) instance.

    This function interacts with the Aruba Central monitoring API to retrieve switch
    data and subsequently synchronizes it with NetBox by applying the appropriate
    role and device type.

    :param ac: Instance of Aruba Central (AC) required for API communication.
    :type ac: object

    :return: None
    """
    path = '/monitoring/v1/switches'
    role = netbox_data['roles']['lan']
    device = 'switches'
    sync_ac(path, device, role)

def aruba_ap_sync(ac):
    """
    Synchronizes Aruba Access Points (APs) with a monitoring system.

    This function integrates with the monitoring API to sync the data related
    to Aruba Access Points. It uses the specified path, device type, and role
    to fetch and sync the AP configurations for the provided Aruba Controller.

    :param ac: Aruba Controller object to perform the synchronization with.
    :type ac: Any
    :return: None
    """
    path = '/monitoring/v2/aps'
    role = netbox_data['roles']['wifi']
    device = 'aps'
    sync_ac(path, device, role)

def load_yaml_files(input_dir: str, yaml_filenames: str) -> dict:
    """
    Load multiple YAML files from the specified directory.
    :param input_dir: Directory containing the YAML files.
    :param yaml_filenames: List of YAML filenames to load.
    :return: A dictionary with the filename (without extension) as the key and its loaded YAML data as the value.
    """
    # Validate input directory
    if not os.path.exists(input_dir):
        raise FileNotFoundError(
            f"The directory '{input_dir}' does not exist. Please create it and add the required YAML files."
        )

    loaded_data = {}
    for yaml_file in yaml_filenames:
        file_path = os.path.join(input_dir, yaml_file)

        # Check if file exists
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"The file '{yaml_file}' does not exist in the directory '{input_dir}'.")

        # Read and safely load the YAML data
        with open(file_path, 'r') as f:
            try:
                loaded_data[yaml_file] = yaml.safe_load(f)
                logger.info(f"Successfully loaded {yaml_file}")
            except yaml.YAMLError as e:
                logger.error(f"Error reading {yaml_file} YAML file: {e}")
                raise ValueError(f"Error reading {yaml_file} YAML file.")

    return loaded_data
def setup_logging(min_log_level=logging.INFO):
    """
    Sets up logging to separate files for each log level.
    Only logs from the specified `min_log_level` and above are saved in their respective files.
    Includes console logging for the same log levels.

    :param min_log_level: Minimum log level to log. Defaults to logging.INFO.
    """
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)

    if not os.access(logs_dir, os.W_OK):
        raise PermissionError(f"Cannot write to log directory: {logs_dir}")

    # Log files for each level
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }

    # Create the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Capture all log levels

    # Define a log format
    log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Set up file handlers for each log level
    for level_name, level_value in log_levels.items():
        if level_value >= min_log_level:
            log_file = os.path.join(logs_dir, f"{level_name.lower()}.log")
            handler = logging.FileHandler(log_file)
            handler.setLevel(level_value)
            handler.setFormatter(log_format)

            # Add a filter so only logs of this specific level are captured
            handler.addFilter(lambda record, lv=level_value: record.levelno == lv)
            logger.addHandler(handler)

    # Set up console handler for logs at `min_log_level` and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(min_log_level)
    console_handler.setFormatter(log_format)
    logger.addHandler(console_handler)

    logging.info(f"Logging is set up. Minimum log level: {logging.getLevelName(min_log_level)}")


if __name__ == '__main__':
    load_dotenv()
    setup_logging(logging.INFO)
    MAX_THREADS = 8
    yaml_filenames = ["netbox.yaml", "firewalls.yaml"]
    config_data = load_yaml_files(os.getenv('INPUT_DIR'), yaml_filenames)
    netbox_data = config_data.get("netbox.yaml")
    firewall_data = config_data.get("firewalls.yaml")
    panorama_ip = os.getenv('PANORAMA_IP')
    pano_username = os.getenv('PANO_USERNAME')
    pano_password = os.getenv('PANO_PASSWORD')
    pano_api_key = os.getenv('PANO_API_KEY')
    DEBUG = os.getenv('DEBUG', False)

    # Aruba Central connectivity
    central_info = {'username': os.getenv('ARUBA_CENTRAL_USERNAME'),
                    'password': os.getenv('ARUBA_CENTRAL_PASSWORD'),
                    'client_id': os.getenv('ARUBA_CENTRAL_CLIENT_ID'),
                    'client_secret': os.getenv('ARUBA_CENTRAL_CLIENT_SECRET'),
                    'customer_id': os.getenv('ARUBA_CENTRAL_CUSTOMER_ID'),
                    'base_url': os.getenv('ARUBA_CENTRAL_BASE_URL')}
    ac = ArubaCentralBase(central_info=central_info, ssl_verify=False)

    # Netbox
    nb = pynetbox.api(netbox_data.get('url'), token=os.getenv('NETBOX_TOKEN'), threading=True)
    nb.http_session.verify = False
    tenant = nb.tenancy.tenants.get(name=netbox_data['tenant'])
    if not tenant:
        logger.critical(f'No tenant found with name {netbox_data["tenant"]}, please create it in Netbox.')
        raise SystemExit(1)
    vrf = nb.ipam.vrfs.get(name=netbox_data['vrf'])
    if not vrf:
        logger.critical(f'No VRF found with name {netbox_data["vrf"]}, please create it in Netbox.')
        raise SystemExit(1)

    # aruba_ap_sync(ac)
    # aruba_switch_sync(ac)
    firewall_sync(panorama_ip, pano_api_key)
