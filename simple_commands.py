# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


"""
THIS FILE CONTAINS THE CLASSES THAT EXECUTE SIMPLE COMMANDS.
    -> Command list class;
    -> Network class;
    -> Get IP class;
    -> IP geolocation class;
    -> MAC to device class.
"""


import socket, ipaddress, json, urllib.request, re
from scapy.all import get_if_list, get_if_addr
from auxiliary import Aux, Argument_Parser_Manager


class Command_List: # ========================================================================================
    """Displays a list of all available commands."""

    def _execute(self, __, _) -> None:
        for i in (
            f'{Aux.green("ip")}........: Get IP by name',
            f'{Aux.green("geoip")}.....: Get geolocation of an IP',
            f'{Aux.green("pscan")}.....: Port scanner',
            f'{Aux.green("netscan")}...: Network scanner',
            f'{Aux.green("macdev")}....: Looks up a MAC'
        ): print(i)





class Network: # =============================================================================================
    """Contains common network-related methods used by multiple classes."""

    @staticmethod
    def _get_ip_by_name(hostname:str) -> str:
        """Get the IP address of a given hostname."""
        try:    ip = socket.gethostbyname(hostname)
        except: ip = Aux.display_error(f'Invalid hostname ({hostname})')
        return  ip
    

    @staticmethod
    def _get_network_interfaces() -> list:
        return get_if_list()
    

    def _get_ip_addresses(self):
        ip_addresses = list()
        try:
            for iface in self._get_network_interfaces():
                ip = get_if_addr(iface)
                if ip: ip_addresses.append(ip)
        except Exception: pass
        return ip_addresses





class Get_IP: # ==============================================================================================
    """Performs a lookup and displays the IP address of a hostname."""

    def _execute(self, auxiliary_data, data:list) -> None:
        """Executes the process to retrieve the IP address based on the provided hostname."""
        try:   argument = self._get_argument(auxiliary_data.parser_manager, data)
        except SystemExit:         print(Aux.display_error("Invalid/missing argument"))
        except Exception as error: print(Aux.display_unexpected_error(error))
        else:  self._ip(argument)


    @staticmethod
    def _get_argument(parser_manager:Argument_Parser_Manager, argument:list) -> str:
        """Parses and retrieves the hostname argument."""
        arguments = parser_manager._parse("Get_Ip", argument)
        return (arguments.host)


    @staticmethod
    def _ip(host_name:str) -> None:
        """Displays the IP address of the provided hostname."""
        print(Network._get_ip_by_name(host_name))





class IP_Geolocation: # ======================================================================================
    """This class performs the geolocation of an IP address."""

    def _execute(self, auxiliary_data, data:list) -> None:
        """Executes the geolocation process and handles errors."""
        try:
            host   = self._get_argument_and_flags(auxiliary_data.parser_manager, data)
            ip     = Network._get_ip_by_name(host)
            data   = self._get_geolocation(ip)
            result = self._process_data(data)
            self._display_result(result)
        except SystemExit: print(Aux.display_invalid_missing())
        except Exception as error: print(Aux.display_unexpected_error(error))


    @staticmethod
    def _get_argument_and_flags(parser_manager:Argument_Parser_Manager, data:list) -> str:
        """Parses arguments and returns the IP address as a string."""
        arguments = parser_manager._parse("GeoIP", data)
        return (arguments.ip)
    
    
    @staticmethod
    def _get_geolocation(ip:ipaddress.IPv4Address) -> dict:
        """Fetches the geolocation information for the given IP address from a web service."""
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json") as response:
            return json.load(response)

    
    @staticmethod
    def _process_data(data:object) -> dict:
        """Processes the geolocation data and extracts specific fields."""
        return {
                "IP":       data.get("ip"),
                "City":     data.get("city"),
                "Region":   data.get("region"),
                "Country":  data.get("country"),
                "Location": data.get("loc"),
                "Postal":   data.get("postal"),
                "Timezone": data.get("timezone")
            }


    @staticmethod
    def _display_result(result:dict) -> None:
        """Displays the processed geolocation results in a formatted manner."""
        for key, value in result.items():
            separator = (8 - len(key)) * '.'
            print(f'{key}{separator}: {value}')





class MAC_To_Device: # =======================================================================================
    """This class displays the manufacturer of devices based on their MAC address."""

    def _execute(self, auxiliary_data, argument:list) -> None:
        """Executes the manufacturer lookup process and handles errors."""
        try: 
            mac    = self._get_argument_and_flags(auxiliary_data.parser_manager, argument)
            mac    = self._normalize_mac(mac)
            result = self._lookup_mac(auxiliary_data.mac_dictionary, mac)
            self._display_result(mac, result)
        except SystemExit: print(Aux.display_invalid_missing())
        except ValueError as error: print(Aux.display_error(error))
        except Exception as error: print(Aux.display_unexpected_error(error))


    @staticmethod
    def _get_argument_and_flags(parser_manager:Argument_Parser_Manager, data:list) -> str:
        """Parses arguments and returns the normalized MAC address as a string."""
        arguments = parser_manager._parse("MacToDev", data)
        return (arguments.mac)
    

    @staticmethod
    def _normalize_mac(mac):
        """Validates the MAC address and returns it in a normalized format."""
        cleaned_mac = re.sub(r'[^a-fA-F0-9]', '', mac)
        if len(cleaned_mac) < 6: raise ValueError("Invalid MAC address")
        normalized_mac = '-'.join([cleaned_mac[i:i+2] for i in range(0, 6, 2)])
        return normalized_mac.upper()


    @staticmethod
    def _lookup_mac(mac_dictionary:list[dict], mac:str) -> None:
        """Looks up the manufacturer associated with the provided MAC address."""
        return mac_dictionary.get(mac, 'Not found')
        

    @staticmethod
    def _display_result(mac:str, result:str) -> None:
        """Displays the manufacturer information based on the MAC address."""
        print(f'MAC: {mac} - Manufacturer: {result}')
