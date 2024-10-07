# DataSeeker

### Description
DataSeeker is a command-line tool that gathers information about devices and networks. Completely made in Python with only one library dependency, it provides an easy-to-use interface for network exploration.


### How to install:
- It does not need to be installed. To use it, just run the code. But the code has two dependencies.

- **Python Installation**: Ensure that you have Python 3.11 or higher installed on your machine. You can download it from [python.org](https://www.python.org/downloads/).

- **Scapy Installation**: The only external dependency is the Scapy library, which can be installed via pip:
  ```
  pip install scapy
  ```
- **Download files**: You can download the files directly from this repository or use git clone:
  ```
  git clone https://github.com/olivercalazans/DataSeeker.git
  ```

### Functionalities:
This code behave like the command-line from linux or windowns. To run a command use the command name, an argument and the flags (optional).
Run the "help" command to see all the commands available.
 - IP: Return an IP of a Hostname;
     ````
     ip <ip_address>
     ````
 - IP Geolocation: Return the geolocation information of an IP;
     ````
     geoip <ip_address> <flags>
     ````
 - MAC to Device: Return the manufacturer of a device by its MAC address;
     ````
     macdev <mac_address>
     ````
 - Port Scanner: Scans a device to discover which ports it has and their status;
     ````
     pscan <ip_address> <flags>
     ````
 - Network Scanner: Maps the network to discover connected devices and information about them;
     ````
     netscan <network_address> <flags>
     ````
