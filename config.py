import configparser
import os
from dataclasses import dataclass

CONFIG_FILE = 'config.ini'

CONFIG_PARAMS = {
    'nmap_port_range': {
        'type': str,
        'description': 'The port range to scan with Nmap.',
        'default': '1-1000',
    },
    'nmap_initial_scan_output': {
        'type': str,
        'description': 'The output file for the initial Nmap scan.',
        'default': 'initial_scan.txt',
    },
    'nmap_initial_scan_options': {
        'type': str,
        'description': 'The Nmap scan options for the initial scan.',
        'default': '-sS -Pn --open -n -vvv',
    },
    'nmap_enum_scan_output': {
        'type': str,
        'description': 'The output file for the Nmap enumeration scan.',
        'default': 'enum_scan.txt',
    },
    'nmap_enum_scan_options': {
        'type': str,
        'description': 'The Nmap scan options for the enumeration scan.',
        'default': '-sV -A -Pn -n -vvv',
    },
    'nmap_full_scan_output': {
        'type': str,
        'description': 'The output file for the full Nmap scan.',
        'default': 'full_scan.txt',
    },
    'nmap_full_scan_options': {
        'type': str,
        'description': 'The Nmap scan options for the full scan.',
        'default': '-sS -Pn -n -vvv -p- --open',
    },
    'target_open_ports': {
        'type': str,
        'description': 'The open ports for the target',
        'default': '',
    },
    'target': {
        'type': str,
        'description': 'The target to scan.',
        'default': '',
    },
    'debug_mode': {
        'type': bool,
        'description': 'Enable debug mode.',
        'default': False,
    },
    'verbose_mode': {
        'type': bool,
        'description': 'Enable verbose mode.',
        'default': False,
    },
}


@dataclass
class PyntesterConfig:
    def __init__(self):
        for param_name, param in CONFIG_PARAMS.items():
            setattr(self, param_name, param['default'])

    def load_from_file(self) -> None:
        if not os.path.exists(CONFIG_FILE):
            raise FileNotFoundError("config.ini not found. Please create one.")

        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)

        for key, value in config['DEFAULT'].items():
            if key not in CONFIG_PARAMS:
                continue

            setattr(self, key, value)

    def get_settable_params(self):
        """
        Get the settable parameters for the CLI.
        """
        return {
            param_name: {
                'type': param['type'],
                'description': param['description'],
                'value': getattr(self, param_name, param['default']),
            }
            for param_name, param in CONFIG_PARAMS.items()
        }.items()
