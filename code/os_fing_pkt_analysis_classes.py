# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import math
from functools import reduce



class TCP_ISN_Greatest_Common_Divisor: # =====================================================================
    
    def __init__(self, isns:list):
        self._isns       = isns
        self._diff1      = list()
        self._gcd        = None


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False
    
    
    def _calculate_diff1_and_gcd(self) -> tuple[list, int]:
        self._calculate_diff1()
        self._calculate_gcd()
        return (self._diff1, self._gcd)


    def _calculate_diff1(self) -> None:
        WRAP_LIMIT = 2 ** 32
        for i in range(len(self._isns) - 1):
            diff         = abs(self._isns[i + 1] - self._isns[i])
            wrapped_diff = WRAP_LIMIT - diff
            self._diff1.append(min(diff, wrapped_diff))


    def _calculate_gcd(self) -> None:
        self._gcd = reduce(math.gcd, self._diff1)





class TCP_ISN_Counter_Rate: # ================================================================================
    
    def __init__(self, diff1:list, times:list):
        self._diff1     = diff1
        self._times     = times
        self._seq_rates = list()
        self._isr       = None


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False
    

    def _calculate_seq_rates_and_isr(self) -> tuple[list, float]:
        self._calculate_sequence_rates()
        self._calculate_isr()
        return (self._seq_rates, self._isr)
    

    def _calculate_sequence_rates(self) -> None:
        for i in range(len(self._diff1)):
            time_diff = self._times[i + 1] - self._times[i]

            if time_diff > 0:
                self._seq_rates.append(self._diff1[i] / time_diff)


    def _calculate_isr(self) -> None:
        if not self._seq_rates:
            return 0
        
        avg_rate = sum(self._seq_rates) / len(self._seq_rates)
        
        if avg_rate < 1:
            return 0
        
        self._isr = round(8 * math.log2(avg_rate))





class TCP_ISN_Sequence_Predictability_Index: # ===============================================================

    def __init__(self, seq_rates:list, gcd:int) -> None:
        self._seq_rates = seq_rates
        self._gcd       = gcd
        self._mean      = None
        self._variance  = None
    

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _calculate_sp(self) -> float | int:
        if len(self._seq_rates) < 4:
            raise ValueError("At least 4 responses are required to calculate SP.")
        
        if self._gcd > 9: 
            self._seq_rates = [rate / self._gcd for rate in self._seq_rates]
        
        self._mean         = self._calculate_mean()
        self._variance     = self._calculate_variance()
        standard_deviation = self._calculate_standard_deviation()
        
        if standard_deviation <= 1: return 0
        else:                       return int(round(math.log2(standard_deviation) * 8))


    def _calculate_mean(self) -> float:
        return sum(self._seq_rates) / len(self._seq_rates)

    def _calculate_variance(self) -> float:
        return sum((x - self._mean) ** 2 for x in self._seq_rates) / len(self._seq_rates)

    def _calculate_standard_deviation(self) -> float:
        return math.sqrt(self._variance)
    




class IP_ID_Sequence_Analyzer: # =============================================================================

    def __init__(self, ip_ids:list[int]):
        self._ip_ids = ip_ids

    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False
    

    def _analyze(self) -> str:
        if not self._ip_ids:
            raise ValueError("No IP ID values provided for analysis.")

        differences = self._calculate_differences()

        # Rule: All ID numbers are zero
        if all(id_ == 0 for id_ in self._ip_ids):
            return "Z"

        # Rule: Any increment >= 20,000 -> Random (RD)
        if any(diff >= 20000 for diff in differences):
            return "RD"

        # Rule: All IDs are identical
        if all(id_ == self._ip_ids[0] for id_ in self._ip_ids):
            return hex(self._ip_ids[0])

        # Rule: Differences > 1,000 and not divisible by 256 -> Random Positive Increments (RI)
        if any(diff > 1000 and diff % 256 != 0 for diff in differences):
            return "RI"

        # Rule: Differences divisible by 256 and <= 5,120 -> Broken Increment (BI)
        if all(diff % 256 == 0 and diff <= 5120 for diff in differences):
            return "BI"

        # Rule: Differences < 10 -> Incremental (I)
        if all(diff < 10 for diff in differences):
            return "I"

        # No matching rules
        return "Test omitted"


    def _calculate_differences(self) -> list[int]:
        differences = []
        for i in range(1, len(self._ip_ids)):
            diff = (self._ip_ids[i] - self._ip_ids[i - 1]) % 65536
            differences.append(diff)
        return differences