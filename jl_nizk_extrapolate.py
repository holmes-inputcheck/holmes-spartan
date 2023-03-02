header = ""
ext_2500 = []
with open('jl_2500_nizk.txt') as f:
    start = True
    for line in f.readlines():
        if start:
            header = line
            start = False
        line = line.rstrip('\n')
        ext_2500.append(line.split(','))

ext_5000 = []
with open('jl_5000_nizk.txt') as f:
    for line in f.readlines():
        line = line.rstrip('\n')
        ext_5000.append(line.split(','))

f100k = open("jl_100000_nizk.txt", "w")
f200k = open("jl_200000_nizk.txt", "w")
f500k = open("jl_500000_nizk.txt", "w")

f100k.write(header)
f200k.write(header)
f500k.write(header)

for i in range(1, len(ext_2500)):
    two_start = float(ext_2500[i][2])
    six_start = float(ext_2500[i][3])
    ten_start = float(ext_2500[i][4])

    two_diff = float(ext_5000[i][2]) - two_start
    six_diff = float(ext_5000[i][3]) - six_start
    ten_diff = float(ext_5000[i][4]) - ten_start

    # euler's method to extrapolate
    # 39 * (5000 - 2500) + 2500 = 100k
    two_100k = two_start + two_diff * 39
    six_100k = six_start + six_diff * 39
    ten_100k = ten_start + ten_diff * 39
    to_write_100k = [ext_2500[i][0], ext_2500[i][1], str(two_100k), str(six_100k), str(ten_100k) + "\n"]
    f100k.write(','.join(to_write_100k))

    # euler's method to extrapolate
    # 79 * (5000 - 2500) + 2500 = 200k
    two_200k = two_start + two_diff * 79
    six_200k = six_start + six_diff * 79
    ten_200k = ten_start + ten_diff * 79
    to_write_200k = [ext_2500[i][0], ext_2500[i][1], str(two_200k), str(six_200k), str(ten_200k) + "\n"]
    f200k.write(','.join(to_write_200k))

    # euler's method to extrapolate
    # 199 * (5000 - 2500) + 2500 = 500k
    two_500k = two_start + two_diff * 199
    six_500k = six_start + six_diff * 199
    ten_500k = ten_start + ten_diff * 199
    to_write_500k = [ext_2500[i][0], ext_2500[i][1], str(two_500k), str(six_500k), str(ten_500k) + "\n"]
    f500k.write(','.join(to_write_500k))

f100k.close()
f200k.close()
f500k.close()

