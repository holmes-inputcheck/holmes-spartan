header = ""
ext_1000 = []
with open('jl_1000_snark.txt') as f:
    start = True
    for line in f.readlines():
        if start:
            header = line
            start = False
        line = line.rstrip('\n')
        ext_1000.append(line.split(','))

ext_2000 = []
with open('jl_2000_snark.txt') as f:
    for line in f.readlines():
        line = line.rstrip('\n')
        ext_2000.append(line.split(','))

f100k = open("jl_100000_snark.txt", "w")
f100k.write(header)

for i in range(1, len(ext_1000)):
    two_start = float(ext_1000[i][2])
    six_start = float(ext_1000[i][3])
    ten_start = float(ext_1000[i][4])

    two_diff = float(ext_2000[i][2]) - two_start
    six_diff = float(ext_2000[i][3]) - six_start
    ten_diff = float(ext_2000[i][4]) - ten_start

    # euler's method to extrapolate
    # 99 * (2000 - 1000) + 1000 = 100k
    two_100k = two_start + two_diff * 99
    six_100k = six_start + six_diff * 99
    ten_100k = ten_start + ten_diff * 99
    to_write_100k = [ext_1000[i][0], ext_1000[i][1], str(two_100k), str(six_100k), str(ten_100k) + "\n"]
    f100k.write(','.join(to_write_100k))

f100k.close()

