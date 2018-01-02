"""
Creates Yara rules for all possible single-byte XOR encoding for a given word.

Example uses the word 'program' so as to find possible encoded executables. 



"""

stringName = 'program'

detection_profiles = []

for i in range(1, 256):
    result = []
    ords = []
    ords_plain = []
    for v in stringName:
        a = chr(ord(v)^i)
        a2 = (ord(v)^i)
        result.append(a)

    new = ''.join(result)
    inhex = new.encode('hex')

    spaced = " ".join(inhex[i:i+2] for i in range(0, len(inhex), 2))

    print 'rule xor_'+hex(i)+'_rule_name {strings: $a={ '+spaced+' } condition: $a }'



