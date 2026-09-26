import xml.etree.ElementTree as ET

def parse_profile(user_xml):
    return ET.fromstring(user_xml)
