"""
"Cometome" Macro Variant # 2" decoder, chall@wapacklabs.com

Instructions -
1.Extract macro using OleVba:
https://bitbucket.org/decalage/oletools/wiki/olevba
example:
olevba.py > vbaoutput.txt

2. Modify the 'path_to_oldeump' parameter below with the path to the Olevba output

Example specimens:
1967c6640203061bea901bf60dd81965c953c0f09c1ee7b678c4365561921c11
61174df59ecd0a83d6cfff327db0378f7d48c8afebc9b5b16c9fbb84294312d5
e7b429647d751c5f182120250a9658283a6a70f257d4b52fc042d83623a993b1


"""


import binascii
import ast

path_to_oledump = 'e7b429647d751c5f182120250a9658283a6a70f257d4b52fc042d83623a993b1'

def xor(data, key):
    l = len(key)
    return bytearray((
        (data[i] ^ key[i % l]) for i in range(0,len(data))
    ))


varmappings = {}
preproc_func = ''
print 'decoding ..'
hex_data = ''
key_ = ''
with open(path_to_oledump) as infile:
    for line in infile:
        line = line.strip()

        if len(line) < 50:
            continue
        temp = line.split('"')
        #print temp
        for t in temp:
            try:
                t.decode("hex")
                hex_data = t
                break
                
            except:
                pass
        for t in temp:
            test = t.split('_')
            try:
                try:
                    if len(test[0])>10 and len(test[1])>10 and ' ' not in test[0]:
                        key_ = t
                        #print 'key!!!!!!!',key
                except:
                    pass
            except:
                pass
                
print hex_data
print 'key:',key_


hexdecode = str(hex_data.decode("hex"))
data = bytearray(hexdecode)

test = [elem.encode("hex") for elem in key_]
keyarray = '[0x'+ ',0x'.join(test)+']'
keyarray = ast.literal_eval(keyarray)

key = bytearray(keyarray)
print '\n'
print 'plaintext:'

print xor(data,key)


