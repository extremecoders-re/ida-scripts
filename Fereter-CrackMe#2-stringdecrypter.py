# String decrypter for CrackMeByFereter #2
# http://crackmes.de/users/fereter/crackme_by_fereter_2/

start = ea = idc.ScreenEA()

# Undefine the current item
idc.MakeUnkn(start, idc.DOUNK_SIMPLE)

while True:
    b = idc.Byte(ea)
    b ^= 0xC6
    idc.PatchByte(ea, b)
    if (b == 0):
        break
    ea += 1

# Convert to string        
idc.MakeStr(start, idc.BADADDR)