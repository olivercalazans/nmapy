# DataSeeker
DataSeeker is a command-line tool that gathers information about devices and networks. Completely made in Python with only one library dependency, it provides an easy-to-use interface for network exploration. This code is designed to run on Linux systems. However, it can also be used on Windows through WSL (I've done some basic testing, but not a full evaluation).

<br>

## How to install: 
It does not need to be installed. To use it, just run the code. **However**, there are two dependencies that need to be installed:
  - **Download files**: You can download the files directly from this repository or use git clone:
    ```bash
    git clone https://github.com/olivercalazans/DataSeeker.git
    ```
  - **1st - Python Installation**: Ensure that you have Python 3.11 or higher installed on your machine. You can download it from [python.org](https://www.python.org/downloads/).
    
  - **2nd - Scapy Installation**: The only external dependency is the Scapy library, which can be installed via pip:
    ```bash
    pip install scapy
    ```
  
<br>

## Functionalities:
This code behaves like the command-line from Linux or Windows. To run a command, use the command name, an argument, and the flags (optional). Run the "help" command to see all the commands available.
- **IP**: Return an IP of a Hostname;
    ```bash
    ip <ip_address>
    ```
- **IP Geolocation**: Return the geolocation information of an IP;
    ```bash
    geoip <ip_address> <flags>
    ```
- **MAC to Device**: Return the manufacturer of a device by its MAC address;
    ```bash
    macdev <mac_address>
    ```
- **Port Scanner**: Scans a device to discover which ports it has and their status;
    ```bash
    pscan <ip_address> <flags>
    ```
- **Network Scanner**: Maps the network to discover connected devices and information about them;
    ```bash
    netscan <network_address> <flags>
    ```
<br>

## Data Sources
This project uses the OUI data provided by the IEEE Standards Association. The data was retrieved from the official IEEE website:
- IEEE OUI Data: [https://standards-oui.ieee.org/](https://standards-oui.ieee.org/)
> Note that the original data has been modified for the purposes of this project.

<br>

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


