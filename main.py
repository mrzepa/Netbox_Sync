import os
import time
import sys
from pycentral.base import ArubaCentralBase
from pycentral.monitoring import Sites
import logging
from dotenv import load_dotenv
from datetime import datetime
import pynetbox
from pynetbox.core.response import Record
import yaml
from icecream import ic
from pypanrestv2.Base import Panorama, Firewall
from pypanrestv2.Network import EthernetInterfaces, TunnelInterfaces, VLANInterfaces, AggregateEthernetInterfaces, DHCPServers
import ipaddress
import warnings
import concurrent.futures
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

_CF_KEY_CACHE: dict[str, str | None] = {}


def _resolve_custom_field_key(nb: pynetbox.api, cache_key: str, candidates: list[str]) -> str | None:
    if cache_key in _CF_KEY_CACHE:
        return _CF_KEY_CACHE[cache_key]

    resolved = None
    for cand in candidates:
        try:
            cf = nb.extras.custom_fields.get(name=cand)
        except Exception:
            cf = None
        if cf:
            resolved = cand
            break

    _CF_KEY_CACHE[cache_key] = resolved
    if resolved is None:
        logger.warning(f"None of the NetBox custom fields exist for {cache_key}: {candidates}")
    return resolved

def _unique_conflict_device_name(desired_name: str, conflicting_device) -> str:
    suffix_parts = ["conflict"]
    device_id = getattr(conflicting_device, "id", None)
    if device_id is not None:
        suffix_parts.append(f"id{device_id}")
    serial = getattr(conflicting_device, "serial", None)
    if serial:
        suffix_parts.append(str(serial)[-6:])
    suffix_parts.append(datetime.utcnow().strftime("%Y%m%d%H%M%S"))
    suffix = "__".join(suffix_parts)
    candidate = f"{desired_name}__{suffix}"
    return candidate[:64]


def _reconcile_netbox_name_collision(nb, *, desired_name: str, site_id: int, tenant_id: int, keep_device_id: int, serial: str):
    try:
        conflicts = nb.dcim.devices.filter(name=desired_name, site_id=site_id, tenant_id=tenant_id)
    except pynetbox.core.query.RequestError as e:
        logger.error(f"Failed to check for NetBox name collisions for {desired_name}: {e}")
        return

    for conflict in conflicts:
        if getattr(conflict, "id", None) == keep_device_id:
            continue

        conflict_serial = getattr(conflict, "serial", None)
        if conflict_serial == serial:
            continue

        new_name = _unique_conflict_device_name(desired_name, conflict)
        try:
            logger.warning(
                f"NetBox name collision for {desired_name} in site_id={site_id}, tenant_id={tenant_id}. "
                f"Renaming conflicting device ID {conflict.id} (serial={conflict_serial}) to {new_name}."
            )
            conflict.name = new_name
            conflict.save()
        except pynetbox.core.query.RequestError as e:
            logger.exception(
                f"Failed to rename conflicting NetBox device ID {conflict.id} from {desired_name} to {new_name}: {e}"
            )
            continue


def _extract_aruba_mac(item: dict) -> str | None:
    for key in ("macaddr", "mac_address", "mac", "eth_mac", "system_mac"):
        val = item.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _extract_aruba_group(item: dict) -> str | None:
    for key in ("group", "group_name", "groupName", "aruba_group"):
        val = item.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _copy_present_fields(src_obj, allowed_fields: list[str]) -> dict:
    payload: dict = {}
    for f in allowed_fields:
        try:
            val = getattr(src_obj, f, None)
        except Exception:
            val = None
        if val is None:
            continue

        # Related objects come through as Records; NetBox expects an ID
        if hasattr(val, "id"):
            payload[f] = val.id
        else:
            payload[f] = val
    return payload


def _normalize_nb_payload(value):
    if value is None:
        return None
    if isinstance(value, Record):
        rec_id = getattr(value, "id", None)
        if rec_id is not None:
            return rec_id
        # Choice-ish Records sometimes have value/name
        rec_val = getattr(value, "value", None)
        if rec_val is not None:
            return rec_val
        rec_name = getattr(value, "name", None)
        if rec_name is not None:
            return rec_name
        return str(value)
    if hasattr(value, "id"):
        return getattr(value, "id", None)
    if isinstance(value, dict):
        return {k: _normalize_nb_payload(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_normalize_nb_payload(v) for v in value]
    return value


def _clone_template_objects(nb, *, endpoint_attr: str, src_device_type_id: int, dst_device_type_id: int,
                           allowed_fields: list[str], strip_poe: bool = False, skip_existing: bool = True):
    endpoint = getattr(nb.dcim, endpoint_attr, None)
    if endpoint is None:
        logger.warning(f"NetBox dcim endpoint '{endpoint_attr}' not available; skipping clone.")
        return

    existing_names: set[str] = set()
    if skip_existing:
        try:
            dst_templates = endpoint.filter(device_type_id=dst_device_type_id)
            for t in dst_templates or []:
                n = getattr(t, "name", None)
                if isinstance(n, str) and n:
                    existing_names.add(n)
        except pynetbox.core.query.RequestError:
            existing_names = set()

    try:
        src_templates = endpoint.filter(device_type_id=src_device_type_id)
    except pynetbox.core.query.RequestError as e:
        logger.error(f"Failed to list {endpoint_attr} for device_type_id={src_device_type_id}: {e}")
        return

    for tmpl in src_templates or []:
        tmpl_name = getattr(tmpl, "name", None)
        if skip_existing and isinstance(tmpl_name, str) and tmpl_name in existing_names:
            continue

        payload = _copy_present_fields(tmpl, allowed_fields)
        payload["device_type"] = dst_device_type_id

        payload = _normalize_nb_payload(payload)

        if strip_poe and endpoint_attr == "interface_templates":
            # Non-PoE models should not have PoE capability flagged
            if "poe_mode" in payload:
                payload["poe_mode"] = None
            if "poe_type" in payload:
                payload["poe_type"] = None

        try:
            endpoint.create(payload)
        except pynetbox.core.query.RequestError as e:
            logger.error(f"Failed to clone {endpoint_attr} template {getattr(tmpl, 'name', None)}: {e}")


def clone_device_type_from_slug(
    nb,
    *,
    source_slug: str,
    new_model: str,
    new_slug: str,
    new_part_number: str | None = None,
    strip_poe: bool = True,
    dry_run: bool = False,
):
    src = nb.dcim.device_types.get(slug=source_slug)
    if not src:
        raise ValueError(f"Source device type slug '{source_slug}' not found in NetBox")

    dst = nb.dcim.device_types.get(slug=new_slug)
    if dst:
        logger.info(f"Target device type slug '{new_slug}' already exists (id={dst.id}); skipping create.")

    manufacturer = getattr(src, "manufacturer", None)
    manufacturer_id = getattr(manufacturer, "id", None)
    if manufacturer_id is None:
        raise ValueError(f"Source device type '{source_slug}' has no manufacturer; cannot clone")

    # Create the new device type
    dt_payload = {
        "manufacturer": manufacturer_id,
        "model": new_model,
        "slug": new_slug,
    }
    if new_part_number:
        dt_payload["part_number"] = new_part_number

    # Copy optional device-type properties when present
    dt_payload.update(
        _copy_present_fields(
            src,
            [
                "u_height",
                "is_full_depth",
                "subdevice_role",
                "airflow",
                "weight",
                "weight_unit",
                "description",
                "comments",
            ],
        )
    )

    if dry_run:
        logger.info(f"DRY RUN: would create device type {new_model} (slug={new_slug}) from {source_slug}")
        return None

    if not dst:
        try:
            dst = nb.dcim.device_types.create(dt_payload)
        except pynetbox.core.query.RequestError as e:
            raise RuntimeError(f"Failed to create device type '{new_model}' (slug={new_slug}): {e}")

        if not dst:
            raise RuntimeError(f"Failed to create device type '{new_model}' (slug={new_slug}); no object returned")

    # Clone templates
    _clone_template_objects(
        nb,
        endpoint_attr="interface_templates",
        src_device_type_id=src.id,
        dst_device_type_id=dst.id,
        allowed_fields=[
            "name",
            "label",
            "type",
            "enabled",
            "mgmt_only",
            "mtu",
            "mode",
            "poe_mode",
            "poe_type",
            "description",
        ],
        strip_poe=strip_poe,
        skip_existing=True,
    )
    _clone_template_objects(
        nb,
        endpoint_attr="console_port_templates",
        src_device_type_id=src.id,
        dst_device_type_id=dst.id,
        allowed_fields=["name", "label", "type", "description"],
        skip_existing=True,
    )
    _clone_template_objects(
        nb,
        endpoint_attr="console_server_port_templates",
        src_device_type_id=src.id,
        dst_device_type_id=dst.id,
        allowed_fields=["name", "label", "type", "description"],
        skip_existing=True,
    )
    _clone_template_objects(
        nb,
        endpoint_attr="power_port_templates",
        src_device_type_id=src.id,
        dst_device_type_id=dst.id,
        allowed_fields=["name", "label", "type", "maximum_draw", "allocated_draw", "description"],
        skip_existing=True,
    )
    _clone_template_objects(
        nb,
        endpoint_attr="power_outlet_templates",
        src_device_type_id=src.id,
        dst_device_type_id=dst.id,
        allowed_fields=["name", "label", "type", "power_port", "feed_leg", "description"],
        skip_existing=True,
    )

    logger.info(
        f"Cloned device type '{source_slug}' (id={src.id}) to '{new_slug}' (id={dst.id}); "
        f"strip_poe={strip_poe}."
    )
    return dst

def _is_public_ip(ip_obj: ipaddress._BaseAddress) -> bool:
    try:
        return bool(ip_obj.is_global)
    except Exception:
        return False

def _get_site_code(site) -> int | None:
    if not site:
        return None
    custom_fields = getattr(site, "custom_fields", None)
    if not isinstance(custom_fields, dict):
        return None
    site_code = custom_fields.get("cf_site_code")
    if site_code is None:
        return None
    try:
        return int(site_code)
    except (TypeError, ValueError):
        return None

def _get_or_create_vrf(nb: pynetbox.api, tenant, vrf_name: str):
    nb_vrf = nb.ipam.vrfs.get(name=vrf_name)
    if nb_vrf:
        return nb_vrf
    try:
        payload = {"name": vrf_name}
        if tenant:
            payload["tenant"] = tenant.id
        nb_vrf = nb.ipam.vrfs.create(payload)
        if nb_vrf:
            logger.info(f"Created VRF {vrf_name} in NetBox with ID: {nb_vrf.id}.")
        return nb_vrf
    except pynetbox.core.query.RequestError as e:
        logger.error(f"Failed to create VRF {vrf_name} in NetBox: {e}")
        try:
            return nb.ipam.vrfs.get(name=vrf_name)
        except Exception:
            return None

def _ip_in_container_prefix(nb: pynetbox.api, ip_obj: ipaddress._BaseAddress) -> bool:
    try:
        candidates = nb.ipam.prefixes.filter(contains=str(ip_obj), status="container")
        return bool(candidates)
    except pynetbox.core.query.RequestError as e:
        logger.error(f"Failed to query container prefixes for IP {ip_obj}: {e}")
        return False

def _find_existing_ip(nb: pynetbox.api, ip_intf: ipaddress._BaseAddress, cidr: str, vrf_id: int | None = None):
    """Find an existing IP address in NetBox, optionally scoped by VRF.

    This avoids cross-VRF collisions so the same IP can exist independently
    in different site-local VRFs.
    """
    try:
        if vrf_id is not None:
            ip_obj = nb.ipam.ip_addresses.get(address=cidr, vrf_id=vrf_id)
        else:
            ip_obj = nb.ipam.ip_addresses.get(address=cidr)
        if ip_obj:
            return ip_obj
    except ValueError:
        # Multiple matches; fall through to filter-based matching
        ip_obj = None
    except pynetbox.core.query.RequestError:
        ip_obj = None

    try:
        if vrf_id is not None:
            matches = nb.ipam.ip_addresses.filter(q=str(ip_intf), vrf_id=vrf_id)
        else:
            matches = nb.ipam.ip_addresses.filter(q=str(ip_intf))
        for m in matches:
            try:
                if str(ipaddress.ip_interface(m.address).ip) == str(ip_intf):
                    return m
            except Exception:
                continue
    except pynetbox.core.query.RequestError:
        return None
    return None

def _get_site_local_role(nb: pynetbox.api):
    """Return the IPAM role object for Site Local prefixes, if it exists."""
    try:
        return nb.ipam.roles.get(name="Site Local")
    except Exception:
        return None

def _ensure_site_local_prefix(nb: pynetbox.api, tenant, vrf_id: int | None, ip_intf: ipaddress.IPv4Interface):
    """Ensure a /24 Site Local prefix exists in the given VRF for the IP.

    This allows the same 192.168.x.0/24 to exist in multiple site-local VRFs
    with role "Site Local".
    """
    # Only handle IPv4 for now and only when we have a VRF context
    if vrf_id is None or not isinstance(ip_intf, (ipaddress.IPv4Interface,)):
        return

    try:
        pfx24 = ip_intf.network.supernet(new_prefix=24)
    except ValueError:
        return

    try:
        prefix = nb.ipam.prefixes.get(prefix=str(pfx24), vrf_id=vrf_id)
    except ValueError:
        # Multiple matches; nothing we can safely fix automatically
        return
    except pynetbox.core.query.RequestError:
        prefix = None

    role = _get_site_local_role(nb)
    role_id = getattr(role, "id", None) if role else None

    if prefix:
        updates = {}
        if role_id is not None and (not getattr(prefix, "role", None) or prefix.role.id != role_id):
            updates["role"] = role_id
        if updates:
            try:
                prefix.update(updates)
            except pynetbox.core.query.RequestError:
                pass
        return

    payload = {
        "prefix": str(pfx24),
        "status": "active",
        "vrf": vrf_id,
    }
    if tenant:
        payload["tenant"] = tenant.id
    if role_id is not None:
        payload["role"] = role_id

    try:
        nb.ipam.prefixes.create(payload)
    except pynetbox.core.query.RequestError:
        return


def _ensure_custom_field_choice(nb: pynetbox.api, cf_name: str, choice_value: str):
    """Ensure a selection-type custom field has a given choice value.

    This is best-effort and will quietly return if the field or its choices
    cannot be safely modified.
    """
    if not choice_value:
        return

    try:
        cf = nb.extras.custom_fields.get(name=cf_name)
    except Exception:
        return

    if not cf:
        return

    # In NetBox, selection values are stored on a CustomFieldChoiceSet, not
    # directly on the CustomField. Find the attached choice set.
    choice_set = getattr(cf, "choice_set", None)
    if not choice_set:
        return

    cs_id = getattr(choice_set, "id", None)
    if cs_id is None:
        return

    try:
        cs = nb.extras.custom_field_choice_sets.get(id=cs_id)
    except Exception:
        return

    if not cs:
        return

    # In newer NetBox, user-defined values live in extra_choices as
    # [[value, label], ...]. Update that list.
    extra = getattr(cs, "extra_choices", None) or []

    normalized = []
    exists = False
    for entry in extra:
        # Expect [value, label]; be defensive about shape
        if isinstance(entry, (list, tuple)) and entry:
            val = entry[0]
            lbl = entry[1] if len(entry) > 1 else entry[0]
        else:
            # Unknown structure; keep as-is and skip matching
            normalized.append(entry)
            continue

        if val == choice_value:
            exists = True
        normalized.append([val, lbl])

    if exists:
        return

    normalized.append([choice_value, choice_value])

    try:
        cs.update({"extra_choices": normalized})
    except pynetbox.core.query.RequestError:
        return

def add_ip_to_interface(ip_entries: list, nb: pynetbox.api, interface_name: str, hostname: str,
                        nb_intf: pynetbox, tenant, site) -> bool:
    """
    Ensure that all firewall IPs are added to a specific NetBox interface without duplicating or affecting unrelated IPs.

    :param ip_entries: A list of dicts representing IP addresses from the firewall,
                       with each dict containing the "@name" key for the IP address in CIDR notation.
    :param nb: An instance of pynetbox.api for interacting with the NetBox API.
    :param interface_name: Name of the interface in NetBox.
    :param hostname: Hostname of the device containing the interface.
    :param nb_intf: NetBox interface object.
    :param tenant: Tenant object.
    :param site: Site object.
    :return: True if the IPs were added successfully, False otherwise.
    """
    # Extract all IPs from the firewall's side (CIDR notation expected)
    firewall_ips = {ip['@name'] for ip in ip_entries}

    # Retrieve only the IPs currently assigned to this specific NetBox interface
    nb_ips = set()
    nb_ip_map = {}
    try:
        # Use filter with precise query: assigned_object_type='dcim.interface', assigned_object_id=<interface_id>
        nb_ip_objs = nb.ipam.ip_addresses.filter(interface_id=nb_intf.id)
        if nb_ip_objs:
            # Collect the exact associated IP addresses (preserve subnet masks) and map to objects
            for nb_ip in nb_ip_objs:
                addr_str = str(nb_ip.address)
                nb_ips.add(addr_str)
                nb_ip_map[addr_str] = nb_ip

    except Exception as e:
        logger.error(f"Failed to retrieve IPs for interface {interface_name} in NetBox: {e}")
        return False

    logger.debug(f"Firewall IPs for {interface_name} on {hostname}: {firewall_ips}")
    logger.debug(f"NetBox IPs for {interface_name} on {hostname}: {nb_ips}")

    # Find missing IPs (with subnet masks preserved)
    missing_ips = firewall_ips - nb_ips

    # Add missing IPs to NetBox
    success = True

    for ip_addr in missing_ips:
        try:
            # Validate IP and subnet mask format
            ip_intf = ipaddress.ip_interface(ip_addr)
            ip_only = ip_intf.ip

            desired_vrf_id = None
            in_container = False
            if interface_name in {"ethernet1/1", "ethernet1/2"} and _is_public_ip(ip_only):
                desired_vrf_id = None
            else:
                if _ip_in_container_prefix(nb, ip_only):
                    in_container = True
                    inet_pri = _get_or_create_vrf(nb, tenant, "INET-PRI")
                    if not inet_pri:
                        logger.error(f"Could not get/create VRF INET-PRI; skipping IP {ip_addr}.")
                        success = False
                        continue
                    desired_vrf_id = inet_pri.id
                else:
                    site_code = _get_site_code(site)
                    if site_code is None:
                        logger.error(f"No valid cf_site_code for site on {hostname}; skipping IP {ip_addr}.")
                        success = False
                        continue
                    site_vrf_name = f"VRF_{site_code}"
                    site_vrf = _get_or_create_vrf(nb, tenant, site_vrf_name)
                    if not site_vrf:
                        logger.error(f"Could not get/create VRF {site_vrf_name}; skipping IP {ip_addr}.")
                        success = False
                        continue
                    desired_vrf_id = site_vrf.id

                    # Ensure the corresponding /24 Site Local prefix exists in this VRF
                    _ensure_site_local_prefix(nb, tenant, desired_vrf_id, ip_intf)

            existing_ip = _find_existing_ip(nb, ip_only, ip_addr, desired_vrf_id)
            if existing_ip:
                assigned_id = getattr(getattr(existing_ip, "assigned_object", None), "id", None)
                if assigned_id and assigned_id != nb_intf.id:
                    if in_container:
                        # For container/INET-PRI space, the firewall is authoritative: reassign
                        logger.warning(
                            f"IP {existing_ip.address} already assigned to another object in NetBox; "
                            f"reassigning to {hostname}:{interface_name} because it is in container space."
                        )
                    else:
                        logger.warning(
                            f"IP {existing_ip.address} already assigned to another object in NetBox; "
                            f"not reassigning to {hostname}:{interface_name}."
                        )
                        continue

                updates = {
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": nb_intf.id,
                    "status": "active",
                }
                if tenant:
                    updates["tenant"] = tenant.id
                if desired_vrf_id is None:
                    updates["vrf"] = None
                else:
                    updates["vrf"] = desired_vrf_id

                try:
                    existing_ip.update(updates)
                    logger.info(f"Updated existing IP {existing_ip.address} on {hostname}:{interface_name} in NetBox.")
                except pynetbox.core.query.RequestError as e:
                    logger.error(f"NetBox API error while updating IP {existing_ip.address}: {e}")
                    success = False
                continue

            logger.info(f"Adding missing IP {ip_addr} to interface {interface_name} in NetBox.")
            payload = {
                "address": f"{ip_addr}",
                "status": "active",
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": nb_intf.id,
            }
            if tenant:
                payload["tenant"] = tenant.id
            if desired_vrf_id is not None:
                payload["vrf"] = desired_vrf_id

            new_addr = nb.ipam.ip_addresses.create(payload)
            if new_addr:
                logger.info(f"Successfully added IP {ip_addr} with ID: {new_addr.id} to NetBox for {interface_name}.")
            else:
                logger.error(f"Failed to add IP {ip_addr} to interface {interface_name} in NetBox.")
                success = False
        except ValueError:
            logger.warning(f"{ip_addr} is not a valid IP address with a subnet mask. Skipping.")
        except pynetbox.core.query.RequestError as e:
            msg = str(getattr(e, "error", e))
            site_name = getattr(site, "name", None)
            logger.error(
                f"NetBox API error while adding IP {ip_addr} on {hostname}:{interface_name} "
                f"(site={site_name}, vrf_id={desired_vrf_id}): {msg}"
            )
            success = False

    # Remove any NetBox IPs not found on the firewall (firewall is source of truth)
    extra_ips = nb_ips - firewall_ips
    for ip_addr in extra_ips:
        ip_obj = nb_ip_map.get(ip_addr)
        if not ip_obj:
            continue
        try:
            logger.warning(
                f"Deleting IP {ip_addr} from NetBox for {interface_name} on {hostname} "
                f"because it is not present on the firewall."
            )
            ip_obj.delete()
        except pynetbox.core.query.RequestError as e:
            logger.error(
                f"Failed to delete stale IP {ip_addr} from NetBox for {interface_name} on {hostname}: {e}"
            )
            success = False

    return success

def find_site_for_ip(ip_address: str):
    """
    Finds the associated site for a given IP address by first determining the /24 prefix
    and then querying the prefix in NetBox. If no prefix or associated site is found,
    appropriate logging is performed, and a corresponding value is returned. Handles
    potential errors such as invalid IP formats or query failures.

    :param ip_address: The input IP address (IPv4 or IPv6) for which the associated site needs to be found.
    :type ip_address: str
    :return: The site object of the prefix of the given IP address if found,
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
        if prefix.scope_type == "dcim.site":
            return prefix.scope
        else:
            logger.error(f"No site associated with prefix {ip_prefix} in NetBox")
            return None
    except ValueError as e:
        # get() returned more than one result. Log all matches and skip.
        try:
            matches = nb.ipam.prefixes.filter(prefix=str(ip_prefix))
        except pynetbox.core.query.RequestError as qe:
            logger.exception(f"Failed to retrieve prefixes for {ip_prefix} after multiple-result error: {qe}")
            return None

        logger.error(f"Multiple prefixes found in NetBox for {ip_prefix}; cannot determine unique site. Error: {e}")
        for pfx in matches or []:
            try:
                scope = getattr(pfx, "scope", None)
                scope_name = getattr(scope, "name", None) if scope else None
                logger.error(f"  Conflicting prefix: {pfx.prefix} scope_type={pfx.scope_type} scope_name={scope_name}")
            except Exception:
                logger.error(f"  Conflicting prefix object: {pfx}")
        return None
    except pynetbox.core.query.RequestError as e:
        logger.exception(f"Failed to retrieve site for prefix {ip_prefix}: {e}")
        return None

def _desired_vrf_id_for_ip(nb: pynetbox.api, tenant, site, interface_name: str, ip_only: ipaddress._BaseAddress):
    if interface_name in {"ethernet1/1", "ethernet1/2"} and _is_public_ip(ip_only):
        return None
    if _ip_in_container_prefix(nb, ip_only):
        inet_pri = _get_or_create_vrf(nb, tenant, "INET-PRI")
        return inet_pri.id if inet_pri else None
    site_code = _get_site_code(site)
    if site_code is None:
        return None
    site_vrf_name = f"VRF_{site_code}"
    site_vrf = _get_or_create_vrf(nb, tenant, site_vrf_name)
    return site_vrf.id if site_vrf else None

def _find_existing_ip_range(nb: pynetbox.api, start_ip: str, end_ip: str, vrf_id: int | None = None):
    try:
        if vrf_id is not None:
            matches = nb.ipam.ip_ranges.filter(q=start_ip, vrf_id=vrf_id)
        else:
            matches = nb.ipam.ip_ranges.filter(q=start_ip)
    except Exception:
        return None

    try:
        desired_start = ipaddress.ip_interface(str(start_ip)).ip
    except ValueError:
        try:
            desired_start = ipaddress.ip_address(str(start_ip))
        except ValueError:
            return None

    try:
        desired_end = ipaddress.ip_interface(str(end_ip)).ip
    except ValueError:
        try:
            desired_end = ipaddress.ip_address(str(end_ip))
        except ValueError:
            return None

    exact_match = None
    wider_same_start = None

    for m in matches:
        try:
            m_start_raw = getattr(m, "start_address", None)
            m_end_raw = getattr(m, "end_address", None)
            if not m_start_raw or not m_end_raw:
                continue
            m_start = ipaddress.ip_interface(str(m_start_raw)).ip
            m_end = ipaddress.ip_interface(str(m_end_raw)).ip

            if str(m_start) == str(desired_start) and str(m_end) == str(desired_end):
                exact_match = m
                break

            # Handle previously mis-created wide ranges (e.g. 10-254/24) by
            # allowing a wider range with the same start IP to be "claimed"
            # and shrunk to the desired end.
            if str(m_start) == str(desired_start) and m_end >= desired_end:
                wider_same_start = m
        except Exception:
            continue

    if exact_match:
        return exact_match
    if wider_same_start:
        return wider_same_start
    return None

def process_firewall(item, pano_api_key, nb, firewall_data, logger, netbox_data, tenant,
                    devices_per_group: dict | None = None,
                    stacks_per_group: dict | None = None):
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

    # Optional: firewall-to-site override mapping from firewall_data
    site_override = None
    for override in firewall_data.get("site_overrides", []) or []:
        if override.get("hostname") == hostname:
            site_override = override
            break

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
        try:
            nb_device_type = nb.dcim.device_types.get(model=model)
            if not nb_device_type:
                raise ValueError(f'Model {model} not found in Netbox. Please add it and try again.')
            nb_device_role = nb.dcim.device_roles.get(name=netbox_data['roles']['firewall'])
            if not nb_device_role:
                raise ValueError(f'Device role {netbox_data["roles"]["firewall"]} not found in Netbox. Please add it and try again.')
            if site_override:
                override_site_name = site_override.get("site")
                site = nb.dcim.sites.get(name=override_site_name) if override_site_name else None
                if not site:
                    logger.warning(f"Site override configured for {hostname} but site '{override_site_name}' not found in NetBox; skipping.")
                    return None
            else:
                site = find_site_for_ip(ip_address)
                if not site:
                    logger.warning(f'No site ID found for device {hostname}, {serial}. Skipping.')
                    return None
            nb_device = nb.dcim.devices.create(
                name=hostname,
                serial=serial,
                device_type=nb_device_type.id,
                role=nb_device_role.id,
                site=site.id,
                status="active",
                tenant=tenant.id,
            )
            if nb_device:
                logger.info(f"Successfully added device {hostname} with ID: {nb_device.id} to NetBox.")
            else:
                logger.error(f"Failed to add device {hostname} to NetBox.")
                return
        except pynetbox.core.query.RequestError as e:
            logger.exception(f"Failed to add device {hostname} to NetBox: {e}")
        except Exception as e:
            logger.exception(f"Failed to add device {hostname} to NetBox: {e}")

    # At this point we have an nb_device; update Panorama-related custom fields
    pano_dev_group = None
    pano_tmpl_stack = None

    if devices_per_group:
        for group_name, serials in devices_per_group.items():
            try:
                if serial in serials:
                    pano_dev_group = group_name
                    break
            except Exception:
                continue

    if stacks_per_group:
        for stack_name, serials in stacks_per_group.items():
            try:
                if serial in serials:
                    pano_tmpl_stack = stack_name
                    break
            except Exception:
                continue

    cf_updates = {}
    if pano_dev_group:
        cf_updates["cf_PanoramaDeviceGroup"] = pano_dev_group
    if pano_tmpl_stack:
        cf_updates["cf_PanoramaTemplateStack"] = pano_tmpl_stack

    if cf_updates:
        current_cfs = getattr(nb_device, "custom_fields", None) or {}
        merged_cfs = {**current_cfs, **cf_updates}
        payload = {"custom_fields": merged_cfs}
        try:
            nb_device.update(payload)
        except pynetbox.core.query.RequestError as e:
            msg = str(getattr(e, "error", e))

            # If the error indicates an invalid/unknown choice for a selection field,
            # try to extend the choice set and retry once. NetBox error messages
            # typically contain the field name and phrases like "Invalid choice".
            if pano_dev_group and ("cf_PanoramaDeviceGroup" in msg and "choice" in msg.lower()):
                _ensure_custom_field_choice(nb, "cf_PanoramaDeviceGroup", pano_dev_group)
            if pano_tmpl_stack and ("cf_PanoramaTemplateStack" in msg and "choice" in msg.lower()):
                _ensure_custom_field_choice(nb, "cf_PanoramaTemplateStack", pano_tmpl_stack)

            try:
                nb_device.update(payload)
            except pynetbox.core.query.RequestError as e2:
                logger.error(
                    f"Failed to update Panorama custom fields on device {hostname} ({serial}) in NetBox: {e2}"
                )

    site = getattr(nb_device, "site", None)

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

    interface_prefixlen: dict[str, int] = {}

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
                    try:
                        if isinstance(ip_entry, list) and ip_entry:
                            ip0 = ip_entry[0].get("@name")
                            if ip0:
                                interface_prefixlen[interface_name] = ipaddress.ip_interface(ip0).network.prefixlen
                    except Exception:
                        pass
                    if not add_ip_to_interface(ip_entry, nb, interface_name, hostname, nb_intf, tenant, site):
                        continue
            elif interface.get("ip"):
                nb_intf = nb.dcim.interfaces.get(name=interface_name, device_id=nb_device.id)
                if not nb_intf:
                    nb_intf = nb.dcim.interfaces.create(name=interface_name, device=nb_device.id, type="virtual")
                ip_entry = interface["ip"]["entry"]
                try:
                    if isinstance(ip_entry, list) and ip_entry:
                        ip0 = ip_entry[0].get("@name")
                        if ip0:
                            interface_prefixlen[interface_name] = ipaddress.ip_interface(ip0).network.prefixlen
                except Exception:
                    pass
                if not add_ip_to_interface(ip_entry, nb, interface_name, hostname, nb_intf, tenant, site):
                    continue
        except IndexError as e:
            logger.exception(f"Failed to get IP address for {hostname}, {serial}, {interface_name}: {e}")
            continue

    if hasattr(getattr(nb, "ipam", None), "ip_ranges"):
        dhcp_entries = []
        for location in ["panorama-pushed", ""]:
            try:
                dhcp_servers = DHCPServers(fw, location=location)
                entries = dhcp_servers.get() or []
                dhcp_entries.extend(entries)
            except Exception as e:
                logger.error(f"Failed to retrieve DHCP servers ({location}) for {hostname}: {e}")

        for dhcp_server in dhcp_entries:
            iface_name = dhcp_server.get("@name") or dhcp_server.get("name")
            if not iface_name:
                continue
            if iface_name in firewall_data["interfaces_to_skip"]:
                continue

            ip_pool = dhcp_server.get("ip-pool") or dhcp_server.get("ip_pool")
            if not isinstance(ip_pool, dict):
                continue
            members = ip_pool.get("member")
            if not isinstance(members, list):
                continue

            prefixlen = interface_prefixlen.get(iface_name)
            if not isinstance(prefixlen, int) or prefixlen < 0:
                logger.warning(f"No interface prefix length found for {hostname}:{iface_name}; skipping DHCP pools on this interface.")
                continue

            for member in members:
                if not isinstance(member, str) or not member:
                    continue
                if "-" in member:
                    parts = member.split("-")
                    if len(parts) != 2:
                        continue
                    start_str, end_str = parts[0].strip(), parts[1].strip()
                else:
                    start_str = end_str = member.strip()

                try:
                    start_ip = ipaddress.ip_address(start_str)
                    end_ip = ipaddress.ip_address(end_str)
                except ValueError:
                    logger.warning(f"Invalid DHCP pool member '{member}' on {hostname}:{iface_name}; skipping.")
                    continue

                desired_vrf_id = _desired_vrf_id_for_ip(nb, tenant, site, iface_name, start_ip)
                if desired_vrf_id is None and not (iface_name in {"ethernet1/1", "ethernet1/2"} and _is_public_ip(start_ip)):
                    logger.error(f"Could not determine VRF for DHCP range {start_ip}-{end_ip} on {hostname}:{iface_name}; skipping.")
                    continue

                start_with_mask = f"{start_ip}/{prefixlen}"
                end_with_mask = f"{end_ip}/{prefixlen}"
                existing_range = _find_existing_ip_range(nb, str(start_ip), str(end_ip), desired_vrf_id)
                payload = {
                    "start_address": start_with_mask,
                    "end_address": end_with_mask,
                    "status": "active",
                }
                if tenant:
                    payload["tenant"] = tenant.id
                if desired_vrf_id is not None:
                    payload["vrf"] = desired_vrf_id
                else:
                    payload["vrf"] = None

                # Infer role from the most specific containing prefix (if any)
                try:
                    prefix_candidates = []
                    if desired_vrf_id is not None:
                        prefix_candidates = nb.ipam.prefixes.filter(contains=str(start_ip), vrf_id=desired_vrf_id)
                    else:
                        prefix_candidates = nb.ipam.prefixes.filter(contains=str(start_ip))
                except Exception:
                    prefix_candidates = []

                best_pfx = None
                best_plen = -1
                for cand in prefix_candidates or []:
                    p = getattr(cand, "prefix", None)
                    role = getattr(cand, "role", None)
                    if not p or not role:
                        continue
                    try:
                        net = ipaddress.ip_network(str(p), strict=False)
                        plen = net.prefixlen
                    except Exception:
                        continue
                    if plen > best_plen:
                        best_plen = plen
                        best_pfx = cand

                if best_pfx and getattr(best_pfx, "role", None):
                    try:
                        payload["role"] = best_pfx.role.id
                    except Exception:
                        pass

                try:
                    if existing_range:
                        existing_range.update(payload)
                    else:
                        nb.ipam.ip_ranges.create(payload)
                except pynetbox.core.query.RequestError as e:
                    msg = str(getattr(e, "error", e))
                    if "overlap" in msg.lower():
                        # Overlapping range exists; since firewall is authoritative,
                        # delete conflicting ranges in this VRF and recreate.
                        logger.warning(
                            f"Overlap detected for DHCP range {start_ip}-{end_ip} in VRF ID {desired_vrf_id} on {hostname}:{iface_name}; "
                            f"deleting conflicting NetBox ranges and recreating from firewall. Details: {msg}"
                        )
                        try:
                            # Fetch candidate ranges in this VRF and delete those that overlap
                            candidates = nb.ipam.ip_ranges.filter(vrf_id=desired_vrf_id) if desired_vrf_id is not None else nb.ipam.ip_ranges.filter(q=str(start_ip))
                        except Exception as fe:
                            logger.error(f"Failed to query overlapping IP ranges for {start_ip}-{end_ip} in VRF ID {desired_vrf_id}: {fe}")
                            continue

                        # First, check if any existing candidate already fully covers the
                        # desired range [start_ip, end_ip]. If so, treat that as
                        # authoritative and skip creating a new, overlapping range to
                        # avoid flapping between equivalent pools on different
                        # interfaces.
                        covers_desired = False
                        try:
                            for r in candidates or []:
                                r_start_raw = getattr(r, "start_address", None)
                                r_end_raw = getattr(r, "end_address", None)
                                if not r_start_raw or not r_end_raw:
                                    continue
                                r_start = ipaddress.ip_interface(str(r_start_raw)).ip
                                r_end = ipaddress.ip_interface(str(r_end_raw)).ip
                                if r_start <= start_ip and r_end >= end_ip:
                                    covers_desired = True
                                    logger.info(
                                        f"Existing DHCP range {r_start}-{r_end} (ID {r.id}) in VRF ID {desired_vrf_id} "
                                        f"already covers desired range {start_ip}-{end_ip} for {hostname}:{iface_name}; skipping create."
                                    )
                                    break
                        except Exception as de:
                            logger.error(f"Failed while evaluating covering ranges in NetBox: {de}")

                        if covers_desired:
                            # Nothing more to do; skip deletion/creation.
                            continue

                        # Otherwise, delete truly overlapping ranges and recreate from
                        # the firewall definition.
                        for r in candidates or []:
                            try:
                                r_start_raw = getattr(r, "start_address", None)
                                r_end_raw = getattr(r, "end_address", None)
                                if not r_start_raw or not r_end_raw:
                                    continue
                                r_start = ipaddress.ip_interface(str(r_start_raw)).ip
                                r_end = ipaddress.ip_interface(str(r_end_raw)).ip
                                # Simple range overlap check
                                if not (end_ip < r_start or start_ip > r_end):
                                    logger.warning(f"Deleting overlapping DHCP range {r_start}-{r_end} (ID {r.id}) in VRF ID {desired_vrf_id}.")
                                    r.delete()
                            except Exception as de:
                                logger.error(f"Failed while evaluating/deleting overlapping range in NetBox: {de}")

                        # Role in payload has already been inferred from the most specific
                        # containing prefix above; reuse that when recreating the range.

                        try:
                            nb.ipam.ip_ranges.create(payload)
                            logger.info(f"Recreated DHCP range {start_ip}-{end_ip} in NetBox for {hostname}:{iface_name} after resolving overlap.")
                        except pynetbox.core.query.RequestError as ce:
                            logger.error(f"Failed to recreate DHCP range {start_ip}-{end_ip} for {hostname}:{iface_name} after deleting overlaps: {ce}")
                    else:
                        logger.error(f"NetBox API error while syncing DHCP range {start_ip}-{end_ip} for {hostname}:{iface_name}: {e}")
    else:
        logger.error("NetBox ip_ranges endpoint not available; skipping DHCP range sync.")

    # Add or update the management IP info
    mgmt_intf = nb.dcim.interfaces.get(name="management", device_id=nb_device.id)
    if not mgmt_intf:
        logger.warning(f"No management interface found for {hostname}, {serial}")
        return
    mgmt_ip = nb.ipam.ip_addresses.get(interface_id=mgmt_intf.id)
    if not mgmt_ip:
        logger.debug(f"No management IP for {hostname}, {serial}")
        mgmt_ip_only = ipaddress.ip_interface(f"{ip_address}/32").ip
        mgmt_vrf_id = _desired_vrf_id_for_ip(nb, tenant, site, "management", mgmt_ip_only)
        if mgmt_vrf_id is None:
            logger.error(f"Could not determine VRF for management IP {ip_address} on {hostname}; skipping management IP create.")
            return
        new_addr = nb.ipam.ip_addresses.create(
            address=f"{ip_address}/24",
            vrf=mgmt_vrf_id,
            tenant=tenant.id,
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
                mgmt_ip_only = ipaddress.ip_interface(f"{ip_address}/32").ip
                mgmt_vrf_id = _desired_vrf_id_for_ip(nb, tenant, site, "management", mgmt_ip_only)
                if mgmt_vrf_id is None:
                    logger.error(f"Could not determine VRF for management IP {ip_address} on {hostname}; skipping management IP update.")
                else:
                    mgmt_ip.update({"address": f"{ip_address}/24", "vrf": mgmt_vrf_id})
                logger.info(f"Updated IP {ip_address} on management interface for {hostname}, {serial} in NetBox.")
            except pynetbox.core.query.RequestError as e:
                logger.error(f"Failed to update IP for management interface on {hostname}, {serial}. Error: {e}")


def firewall_sync(panorama_ip, pano_api_key):
    # Connect to Panorama
    pano = Panorama(panorama_ip, api_key=pano_api_key)

    # Get a list of all the firewalls connected to Panorama
    firewall_list = pano.get_firewall_connected()
    template_stacks = pano.op('show template-stack')
    device_groups = pano.op('show devicegroups')
    devices_per_group = get_devices_by_container(device_groups)
    stacks_per_group = get_devices_by_container(template_stacks)

    # Run the firewall processing loop in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [
            executor.submit(process_firewall, item, pano_api_key, nb, firewall_data, logger, netbox_data, tenant, devices_per_group, stacks_per_group)
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
        mac_cf_key = _resolve_custom_field_key(nb, "aruba_mac", ["cf_MAC", "MAC", "mac"]) 
        group_cf_key = _resolve_custom_field_key(
            nb,
            "aruba_group",
            ["cf_ArubaCentralGroup", "ArubaCentralGroup", "aruba_central_group", "ArubaGroup"],
        )

        for item in device_list:
            model = item['model']
            name = item['name']
            serial = item['serial']
            site = item['site']

            aruba_mac = _extract_aruba_mac(item)
            aruba_group = _extract_aruba_group(item)
            if device == 'switches':
                if item['stack_id']:
                    name = f'{name} - stack member {item["serial"]}'
            nb_site = nb.dcim.sites.get(name=site)
            if not nb_site:
                logger.warning(f'Site "{site}" not found in Netbox, skipping...')
                continue
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
                try:
                    _reconcile_netbox_name_collision(
                        nb,
                        desired_name=name,
                        site_id=nb_site.id,
                        tenant_id=tenant.id,
                        keep_device_id=-1,
                        serial=serial,
                    )

                    cf_updates = {}
                    if mac_cf_key and aruba_mac:
                        cf_updates[mac_cf_key] = aruba_mac
                    if group_cf_key and aruba_group:
                        cf_updates[group_cf_key] = aruba_group

                    nb_device = nb.dcim.devices.create(name=name,
                                                       device_type=device_type.id,
                                                       role=device_role.id,
                                                       site=nb_site.id,
                                                       status='active',
                                                       serial=serial,
                                                       tenant_id=tenant.id,
                                                       custom_fields=cf_updates if cf_updates else None)
                    if nb_device:
                        logger.info(f'Succesfully added device {name} with ID: {nb_device.id} to Netbox.')
                    else:
                        logger.error(f'Failed to add device {name} to Netbox.')
                except pynetbox.core.query.RequestError as e:
                    logger.exception(f'Could not add device {name} to Netbox: {e}')
            else:
                # the device exists in netbox, lets see if it's name or site has changed
                if (nb_device.name != name) or (nb_device.site.id != nb_site.id):
                    _reconcile_netbox_name_collision(
                        nb,
                        desired_name=name,
                        site_id=nb_site.id,
                        tenant_id=tenant.id,
                        keep_device_id=nb_device.id,
                        serial=serial,
                    )

                cf_updates = {}
                if mac_cf_key and aruba_mac:
                    cf_updates[mac_cf_key] = aruba_mac
                if group_cf_key and aruba_group:
                    cf_updates[group_cf_key] = aruba_group

                if cf_updates:
                    current_cfs = getattr(nb_device, "custom_fields", None) or {}
                    merged_cfs = {**current_cfs, **cf_updates}
                    payload = {"custom_fields": merged_cfs}
                    try:
                        nb_device.update(payload)
                    except pynetbox.core.query.RequestError as e:
                        msg = str(getattr(e, "error", e))
                        if group_cf_key and aruba_group and (group_cf_key in msg and "choice" in msg.lower()):
                            _ensure_custom_field_choice(nb, group_cf_key, aruba_group)
                        try:
                            nb_device.update(payload)
                        except pynetbox.core.query.RequestError as e2:
                            logger.error(
                                f"Failed to update Aruba Central custom fields on device {name} ({serial}) in NetBox: {e2}"
                            )

                if nb_device.name != name:
                    nb_device.name = name
                    logger.info(
                        f'Device with serial number {serial} and name {name} updated in Netbox with ID {nb_device.id} with name {nb_device.name}.')

                if nb_device.site.id != nb_site.id:
                    nb_device.site = nb_site.id
                    nb_device.location = None
                    logger.info(f'Device with serial number {serial} and name {name} updated in Netbox to site {nb_site}.')
                try:
                    nb_device.save()
                except pynetbox.core.query.RequestError as e:
                    logger.exception(f'Could not update device {name} in Netbox: {e}')
                    continue


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

def freshservice_subnets_to_netbox_sync(fs_asset_type_name: str):

    fs_asset_type = fs.asset_types.get(name=fs_asset_type_name)
    filters = {'asset_type_id': fs_asset_type.item_id, }
    azure_subnets = fs.assets.view_list(filters=filters)
    for azure_subnet in azure_subnets:
        name = azure_subnet['name']
        prefix = azure_subnet.get('type_fields', {}).get('cidr_block_22000291124')
        network_name = azure_subnet.get('type_fields', {}).get('network_name_22000291169')
        # network_name will be the netbox ipam role, if role does not exist, create it.
        # prefix will be the netbox prefix to create
        # name will be the description in the prefix.

from typing import Dict, List, Optional

def get_devices_by_container(op_result: dict, explicit_key: Optional[str] = None) -> Dict[str, List[str]]:
    """
    Generic extractor for Panorama op outputs that look like:
        { "status": "success",
          "result": {
              "template-stack" or "devicegroups": {
                  "entry": [ { "@name": ..., "devices": { "entry": ... } }, ... ]
              }
          }
        }

    Returns:
        { container_name: [serial1, serial2, ...], ... }

    `explicit_key` can be "template-stack" or "devicegroups" to override auto-detection.
    """
    result_root = op_result.get("result", {})

    # Auto-detect the key if not provided
    key = explicit_key
    if key is None:
        if "template-stack" in result_root:
            key = "template-stack"
        elif "devicegroups" in result_root:
            key = "devicegroups"
        else:
            # Nothing we know how to handle
            return {}

    containers = result_root.get(key, {}).get("entry", [])

    # If only one entry exists, it might be a dict instead of a list
    if isinstance(containers, dict):
        containers = [containers]

    out: Dict[str, List[str]] = {}

    for container in containers:
        name = container.get("@name")
        if not name:
            continue

        devices = container.get("devices", {}).get("entry", [])

        # Normalize single-vs-list devices
        if isinstance(devices, dict):
            devices = [devices]

        serials: List[str] = []
        for dev in devices:
            serial = dev.get("serial")
            if serial:
                serials.append(serial)

        out[name] = serials

    return out


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

    # Freshservice
    # fs = FreshService(os.getenv("FRESHSERVICE_URL"), os.getenv("FRESHSERVICE_API_KEY"))

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

    aruba_ap_sync(ac)
    aruba_switch_sync(ac)
    # firewall_sync(panorama_ip, pano_api_key)

    # clone_device_type_from_slug(
    #     nb,
    #     source_slug="6200f-48g-4sfpp",
    #     new_model="6200F 48G 4SFP+ Swch (JL726B)",
    #     new_slug="6200f-48g-4sfpp-jl726b",
    #     new_part_number="JL726B",
    #     strip_poe=True,
    # )