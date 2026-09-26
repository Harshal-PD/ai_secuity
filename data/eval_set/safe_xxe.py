import xml.etree.ElementTree as ET

STATIC_CONFIG = "<config><debug>false</debug></config>"

def load_default_config():
    # parses a compile-time constant, never external input
    return ET.fromstring(STATIC_CONFIG)
