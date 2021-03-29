
with open("headings.txt", 'r') as f:
    line = f.readline()
    linearr = line.split(",")

with open("features.txt", 'r') as f:
    for line in f:
        print(linearr.index(line.split(" ")[len(line.split(" "))-1].rstrip()), end=',')
