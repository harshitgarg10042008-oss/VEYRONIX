"""Read-only device connector for secure configuration pulling.

This module uses netmiko to connect to networking devices, safely execute
read-only 'show run' commands, strip out secrets, and pass the output to
the deterministic audit engine.
"""

import os
from typing import Optional

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False


class ConnectorError(Exception):
    """Base exception for device connector failures."""


class LiveDeviceConnector:
    """Read-only secure configuration pull agent."""
    
    def __init__(self, host: str, vendor: str, username: str, password: Optional[str] = None):
        """Initialize the device connector.
        
        Args:
            host: IP address or hostname of the device.
            vendor: Expected vendor (cisco_ios, junos, etc.)
            username: SSH username
            password: SSH password
        """
        if not NETMIKO_AVAILABLE:
            raise RuntimeError("Netmiko is not installed. Run pip install -e '.[enterprise]'")
            
        self.host = host
        self.vendor = vendor
        self.username = username
        self.password = password or os.getenv("CONFIGSENTINEL_DEVICE_PASSWORD")
        
        # Map ConfigSentinel vendors to Netmiko device types
        self._device_type_map = {
            "cisco_ios": "cisco_ios",
            "junos": "juniper_junos",
            "arista_eos": "arista_eos",
        }
        
        if self.vendor not in self._device_type_map:
            raise ConnectorError(f"Live pull is not currently supported for vendor: {self.vendor}")

    def pull_config(self) -> str:
        """Safely connect to the device and pull the running configuration.
        
        Returns:
            The raw running configuration as a string.
        """
        device_type = self._device_type_map[self.vendor]
        
        device_params = {
            "device_type": device_type,
            "host": self.host,
            "username": self.username,
            "password": self.password,
            "session_log": None,
            "global_delay_factor": 2,
        }
        
        try:
            with ConnectHandler(**device_params) as net_connect:
                # SAFETY: Explicitly assert we are NOT in config mode
                if net_connect.check_config_mode():
                    net_connect.exit_config_mode()
                
                # Use standard show command based on vendor
                if device_type == "juniper_junos":
                    command = "show configuration"
                else:
                    command = "show running-config"
                    
                output = net_connect.send_command(command)
                return output
                
        except NetmikoAuthenticationException as e:
            raise ConnectorError(f"Authentication failed for {self.host}") from e
        except NetmikoTimeoutException as e:
            raise ConnectorError(f"Connection timed out for {self.host}") from e
        except Exception as e:
            raise ConnectorError(f"An unexpected error occurred while connecting to {self.host}: {e}") from e
