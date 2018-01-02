"""
"Cometome" Macro Variant # 1" decoder, chall@wapacklabs.com

Instructions -
1.Extract macro using OleVba:
https://bitbucket.org/decalage/oletools/wiki/olevba
example:
olevba.py > vbaoutput.txt

2. Modify the 'path_to_oldeump' parameter below with the path to the Olevba output

Example specimens:
81e75fc5f5d4127747c14df260a47b712fb1f0f094e6e3b9f49f7cc917b229ea
a852d6e76e2fea14812be48732770f5071fd7e652dc30169f5688f5a973ad569
"""


import binascii
import ast

path_to_oledump = 'a852d6e76e2fea14812be48732770f5071fd7e652dc30169f5688f5a973ad569'#must be olevba output,not original specimen

def xor(data, key):
    l = len(key)
    return bytearray((
        (data[i] ^ key[i % l]) for i in range(0,len(data))
    ))


varmappings = {}
preproc_func = ''
print 'decoding ..'
with open(path_to_oledump) as infile:
    for line in infile:
        line = line.strip()
        if ' = "' in line:
            temp = line.split(' = ')
            temp2 = temp[1].replace('"', '')
            varmappings[temp[0]] = temp2
        testfunc = line.split(' & ')
        if len(testfunc) >= 10:
            preproc_func = line


key_ = preproc_func.split('"')[1]
print 'key:',key_

vars_ = preproc_func.split(' & ')

var_list = []
count_ = 0
for v in vars_:
    count_ += 1
    if count_ == 1:
        v = v.split(', ')[1]
    if v.endswith(')'):
        var_list.append(v[:-1])
    else:
        var_list.append(v)
#print '~~~~~~~'
#print var_list

hex_data = []
for v in var_list:
    chunk = varmappings[v]
    hex_data.append(chunk)

hex_data = ''.join(hex_data)
#print hex_data


hexdecode = str(hex_data.decode("hex"))
data = bytearray(hexdecode)

test = [elem.encode("hex") for elem in key_]
keyarray = '[0x'+ ',0x'.join(test)+']'
keyarray = ast.literal_eval(keyarray)

key = bytearray(keyarray)
print '\n'
print 'plaintext:'

print xor(data,key)


