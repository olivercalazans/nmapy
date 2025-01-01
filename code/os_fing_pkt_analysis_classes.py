# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from math import log2, sqrt


class Sequence_Predictability_Index:
    """ TCP ISN sequence predictability index (SP) """

    def __init__(self, seq_rates:list, gcd:int) -> None:
        self._seq_rates = seq_rates
        self._gcd       = gcd
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _calculate_sp(self) -> None:
        if len(self._seq_rates) < 4:
            raise ValueError("At least 4 responses are required to calculate SP.")
        
        if self._gcd > 9: 
            self._seq_rates = [rate / self._gcd for rate in self._seq_rates]
        
        mean     = self._calculate_mean()
        variance = self._calculate_variance(mean)
        std_dev  = self._calculate_standard_deviation(variance)
        
        if std_dev <= 1: sp = 0
        else:            sp = int(round(log2(std_dev) * 8))
        
        return sp


    def _calculate_mean(self) -> float:
        return sum(self._seq_rates) / len(self._seq_rates)

    def _calculate_variance(self, mean:float) -> float:
        return sum((x - mean) ** 2 for x in self._seq_rates) / len(self._seq_rates)

    @staticmethod
    def _calculate_standard_deviation(variance:float) -> float:
        return sqrt(variance)