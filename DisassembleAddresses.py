# Disassembles all addresses from a text file. Each address should be in hex and on it's own line.
#@author Paramjot (PJ) Oberoi, Oberoi Security Solutions
#@category Data

fileName = askFile("Choose addresses file:", "OK")

print("Loading file:" + fileName.path)

for line in file(fileName.absolutePath):
    pieces = line.split()
    address = toAddr(long(pieces[0], 16))
    print "Disassembling: 0x" + str(address)
    disassemble(address)
