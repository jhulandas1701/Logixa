from .cisco_asa import CiscoASAParser
from .fortigate import FortiGateParser
from .suricata import SuricataEVEParser
from .apache import ApacheAccessParser
from .nginx import NginxAccessParser
from .linux_auth import LinuxAuthParser
from .security_device import SecurityDeviceParser

PARSERS = {
    'cisco_asa': CiscoASAParser(),
    'fortigate': FortiGateParser(),
    'suricata_eve': SuricataEVEParser(),
    'apache': ApacheAccessParser(),
    'nginx': NginxAccessParser(),
    'linux_auth': LinuxAuthParser(),
    'security_device': SecurityDeviceParser(),
}
