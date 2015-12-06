#!/usr/bin/env python3

maxmul = int(input("Enter max mul number (256): "))
maxdiv = int(input("Enter max div number (256): "))
rangemin = float(input("Enter range min: "))
rangemax = float(input("Enter range max: "))
clval = float(input("Enter clock value: "))

freqlst = []
freqlststr = []
for mulval in range(maxmul):
    mulval += 1
    for divval in range(maxdiv):
        divval += 1
        freqres = (clval * mulval) / divval
        if freqres > rangemin and freqres < rangemax:
            freqlst += [(clval * mulval) / divval]
            freqlststr += ["({0}*{1})/{2}".format(clval, mulval, divval)]
freqlst, freqlststr = zip(*sorted(zip(freqlst, freqlststr)))
for ind in range(len(freqlst)):
    freqstr = str(freqlst[ind])
    print(freqstr + (" " * (20 - len(freqstr))) + " --- " + str(freqlststr[ind]))

#[0.032000, 0.032768, 0.038000, 0.077500, 0.100000, 0.120000, 0.131072, 1.000000, 1.008, 1.544, 1.8432, 2.048000, 2.097152, 2.4576, 2.500, 2.560, 2.880, 3.072000, 3.088, 3.2768, 3.575611, 3.579545, 3.582056, 3.595295, 3.64, 3.686400, 3.93216, 4.000, 4.032, 4.096000, 4.194304, 4.332, 4.43361875, 4.608, 4.8970, 4.9152, 5.000, 5.034963, 5.0688, 5.120, 5.185, 5.5296, 5.6448, 6.000, 6.063, 6.144, 6.176, 6.400, 6.451200, 6.4983, 6.5536, 6.7458, 7.023, 7.15909, 7.200, 7.3728, 8.000, 8.184, 8.192000, 8.4672, 8.664, 8.86724, 9.216, 9.54545, 9.600, 9.83040, 10.000, 10.2300, 10.24, 10.245, 10.368, 10.416667, 11.0592, 11.2896, 11.454544, 11.520, 12.0000, 12.272727, 12.288, 12.352, 12.40625, 12.800, 12.9024, 12.960, 13.000, 13.500, 13.5168, 13.56, 13.824, 13.875, 14.112, 14.25, 14.31818, 14.35, 14.400, 14.7456, 14.75, 14.85, 15.000, 15.360, 15.600, 16.000, 16.200, 16.257, 16.3676, 16.367667, 16.3680, 16.369, 16.384000, 16.5888, 16.67, 16.800, 16.9344, 17.328, 17.664, 17.734475, 18.432, 18.816, 19.200, 19.44, 19.6608, 19.6800, 19.800, 20.000]
