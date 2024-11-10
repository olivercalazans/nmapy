# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...



from network   import Network
from auxiliary import Argument_Parser_Manager, Color



class OS_Fingerprint:
    def __init__(self) -> None:
        self._target_ip = None


    def _execute(self, database, data:list) -> None:
        try:
            self._get_argument(database.parser_manager, data)
            self._perform_icmp_fingerprint()
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except KeyboardInterrupt:   print(Color.red("Process stopped"))
        except Exception as error:  print(Color.display_unexpected_error(error))

    
    def _get_argument(self, parser_manager:Argument_Parser_Manager, argument:list) -> str:
        arguments = parser_manager._parse("OSFingerprint", argument)
        self._target_ip = arguments.target
    

    def _perform_icmp_fingerprint(self) -> None:
        print(f"Performing OS fingerprinting with ICMP on {self._target_ip}...")
        packet   = Network._create_ip_icmp_packet(self._target_ip)
        response = Network._send_single_packet(packet)
        if response:
            ttl = response.ttl
            self._identify_os_by_icmp(ttl)
        else:
            print("No ICMP response received from the target.")


    @staticmethod
    def _identify_os_by_icmp(ttl) -> None:
        if ttl <= 64:    print("Probably Linux/Android")
        elif ttl <= 128: print("Probably Windows")
        elif ttl > 128:  print("Probably iOS or another system with a higher TTL")
        else: print("Unknown operating system")
