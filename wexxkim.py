"""
Works against variant of macro similar-to the following:

00ccefebd05db1cd2c9ad024ccad25b0
0b0aac1bbf3b025dbceb24d66ea7c406
0da7a82d4e0079d60856e5f7f323d673

.BAS macro files must first be extracted with olevba:
https://www.decalage.info/python/olevba

"""


import os
import math
ns = vars(math).copy()
ns['__builtins__'] = None

vb1 = 'yoaezuu.bas'
vb2 = 'wexxkim.bas'

#vb1 = 'nqhcs.bas'
#vb2 = 'wmrlt.bas'

vb2_name = vb2.split('.')[0]

char_lookup = {}

print 'pulling variable values from macro 2 '
with open(vb2) as infile:
    
    for line in infile:
        line = line.strip()

        if ' = ' in line:
            try:
                int(line.split(' = ')[1].split(' ')[0])
                first = line.split(' = ')[1].split(' ')[0]
                second = line.split(' = ')[1].split(' ')[2]
                var_ = line.split(' = ')[0].strip()
                equation = line.split(' = ')[1]
                result = eval(equation, ns)
                char_lookup[var_] = result
            except Exception, e:
                print e


with open(vb1) as infile:  
    for line in infile:
        line = line.strip()
        if ' & chrw(' in line:
            temp = line.split(' = ')[0]
            str_decode_param = temp
            break


print 'processing main macro..'

test_decode = []
with open(vb1) as infile:  
    for line in infile:
        line = line.strip()
        if line.startswith(str_decode_param):
            temp_vals = []            
            temp = line.split(vb2_name)
            for t in temp:
                if t.startswith('.') and t.endswith(')'):
                    temp_vals.append(t[1:-1])
                elif not t.startswith(str_decode_param):
                    t2 = t.split(') &')[0][1:]
                    temp_vals.append(t2)
            for t in temp_vals:
                int_val = char_lookup[t]
                chr_val = chr(int_val)
                test_decode.append(chr_val)
            
print 'decoded URL:'
test_decode = ''.join(test_decode)
print test_decode
