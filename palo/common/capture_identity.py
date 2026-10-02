"""Identify retained PAN-OS evidence without inferring manager/device equivalence."""
from xml.etree import ElementTree as ET

MAX_BYTES = 128 * 1024 * 1024


def native_identity(kind, payload, serial):
    """Return matching, conflicting, or unverified from explicit native serials.

    An identity response proves only the system-info capture. It must never
    authenticate a different response merely because filenames share a serial.
    """
    if kind not in {'identity', 'local_configuration'} or not isinstance(payload, bytes):
        return 'unverified'
    if len(payload) > MAX_BYTES:
        return 'unverified'
    try:
        text = payload.decode('utf-8-sig')
        if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            return 'unverified'
        root = ET.fromstring(text)
    except (ValueError, UnicodeError, ET.ParseError):
        return 'unverified'
    if root.tag == 'response':
        if root.get('status') != 'success':
            return 'unverified'
        if kind == 'identity':
            values = {node.text.strip() for node in root.findall('./result/system/serial')
                      if node.text and node.text.strip()}
            return 'matching' if values == {serial} else 'conflicting' if values else 'unverified'
        root = root.find('./result/config')
    if kind != 'local_configuration' or root is None or root.tag != 'config':
        return 'unverified'
    # Panorama inventory/assignments are not the firewall's local identity.
    if root.find('./devices/entry/device-group') is not None or root.find('./mgt-config/devices') is not None:
        return 'unverified'
    values = {value.strip() for value in [root.get('serial', ''), root.findtext('./serial', ''),
              root.findtext('./devices/entry/deviceconfig/system/serial-number', '')] if value.strip()}
    return 'matching' if values == {serial} else 'conflicting' if values else 'unverified'
