# -*- coding: cp1252 -*-

"""
Examples of simple URL encoding in malware including:
 - Hex ASCII 
 - Simple base64 
 - Integer (popular in macro malware)
 
Also trys to find single byte encoding patterns
"""

import re
import base64




sample_strings =['aHR0cDovL3N0YWNrb3ZlcmZsb3cuY29tL3F1ZXN0aW9ucy85NjQxNDQwL2NvbnZlcnQtZnJvbS1hc2NpaS1zdHJpbmctZW5jb2RlZC1pbi1oZXgtdG8tcGxhaW4tYXNjaWk=',
 '596D7868614342696247466F49476830644841364C7939305A584E3064584A734C6D4E766253396B59584E6B5A6D467A5A43356C65475567596D4673614342696247466F',
 '626C616820626C616820687474703A2F2F7465737475726C2E636F6D2F64617364666173642E6578652062616C6820626C6168',
 "[104, 116, 116, 112, 58, 47, 47, 97, 110, 111, 116, 104, 101, 114, 116, 101, 115, 116, 117, 114, 108, 46, 99, 111, 109, 47, 116, 101, 115, 116, 46, 101, 120, 101, 95, 100, 97, 102, 115, 100, 102]",
 '61616161616161616971716E6C7070',
 'baaaaaaaiqqnlppssssssaada',
 '33333333333333333333333333333333333333333333333333333',
 'https://test.com.com/dafasdfsad.exe']


pattern_checks = [['hexapattern',r'([0-9a-fA-F]{10,})'],
 ['base64pattern',r'([A-Za-z0-9+/=]{10,})'],
 ['integerpattern',r'([0-9]{2,})']]


def find_encoded_http(string):
    string_array = []
    result_array = []
    for i in string:
        #print i
        string_array.append(str(ord(i)))
        #print str(ord(i))

    counter = 0
    #print string_array
    for s in string_array[1:]:
        counter += 1
        try:
            if (string_array[counter]==string_array[counter+1] and
                string_array[counter-1] != string_array[counter] and
                string_array[counter]!=string_array[counter+2] and
                string_array[counter+4]==string_array[counter+5] and
                string_array[counter+3]!=string_array[counter+4]):                
                result_array.append(string[counter-1:])
                #print string[counter-1:]
                #return result_array

                #return string[counter-1:]
        except:
            #raise
            pass
    if len(result_array) != 0:
        #print 'reversed'
        return result_array
    string_array = []
    string = string[::-1] # check in reverse order
    for i in string:
        #print i
        string_array.append(str(ord(i)))
        #print str(ord(i))

    counter = 0
    #print string_array
    for s in string_array[1:]:
        counter += 1
        try:
            if (string_array[counter]==string_array[counter+1] and
                string_array[counter-1] != string_array[counter] and
                string_array[counter]!=string_array[counter+2] and
                string_array[counter+4]==string_array[counter+5] and
                string_array[counter+3]!=string_array[counter+4]):                
                result_array.append(string[counter-1:])
                #print string[counter-1:]
                #return result_array

                #return string[counter-1:]
        except:
            #raise
            pass
    if len(result_array) != 0:
        #print 'reversed'
        return result_array
    return False

urlpattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

def decode_layer2(strings,match_type,recurse):
    decode_array = []
    no_match_array = []
    intprocess = []
    if match_type == 'hexapattern':
        for s in strings:            
            try:
                decoded = s.decode("hex")                
                url_test = re.findall(urlpattern, decoded)
                #print url_test
                if len(url_test) != 0:
                    decode_array.append([match_type,'decoded_url',url_test])
                if len(url_test) == 0 and find_encoded_http(decoded) is not False:
                    decode_array.append([match_type,'encoded_url_pattern',find_encoded_http(decoded)])

                no_match_array.append([match_type,'no_match',decoded])

            except:
                pass
            if len(decode_array) != 0:
                return decode_array
            else:
                return no_match_array
    if match_type == 'base64pattern':
        for s in strings:
            try:
                decoded = s.decode("base64")
                url_test = re.findall(urlpattern, decoded)
                if len(url_test) != 0:
                    decode_array.append([match_type,'decoded_url',url_test])
                if len(url_test) == 0 and find_encoded_http(decoded) is not False:
                    decode_array.append([match_type,'encoded_url_pattern',find_encoded_http(decoded)])
                no_match_array.append([match_type,'no_match',decoded])
                
            except:
                pass
            if len(decode_array) != 0:
                return decode_array
            else:
                return no_match_array
    if match_type == 'integerpattern':
        for s in strings:
            try:
                if len(s) >= 3:
                    s = s[-3:]
                    s.lstrip('0')
                s = int(s)
                c = str(chr(s))
                intprocess.append(c)

            except:
                #raise
                pass
    #print decode_array
    if match_type == 'integerpattern':
        #new_decode_array = []
        decoded = ''.join(intprocess)
        #print decoded
        url_test = re.findall(urlpattern, decoded)
        #print url_test
        if len(url_test) != 0:
            decode_array.append([match_type,'decoded_url',url_test])
            #print decode_array
        if len(url_test) == 0 and find_encoded_http(decoded) is not False:
            decode_array.append([match_type,'encoded_url_pattern',find_encoded_http(decoded)])
            
        no_match_array.append([match_type,'no_match',decoded])
        if len(decode_array) != 0:
            return decode_array
        else:
            return no_match_array


def process_string(s,recurse):
    all_results = []


    for p in pattern_checks:
        match_type = p[0]
        regex = p[1]
        matches = re.findall(regex, s)
        #print matches
        if len(matches) != 0:
            #print s
            #print match_type
            #print matches
            decode_hits = decode_layer2(matches,match_type,recurse)
            if len(decode_hits) != 0:
                #print match_type
                all_results.append(decode_hits)
            '-------------------------------'
    if len(all_results) == 0:
        url_test = re.findall(urlpattern, s)
        if len(url_test) != 0:
            all_results.append([['plaintext','url',url_test]])
        if len(url_test) == 0 and find_encoded_http(s) is not False:
            all_results.append([['simple','encoded_url_pattern',find_encoded_http(s)]])

    return all_results


for e in sample_strings:
    recurse = ''
    r = process_string(e,recurse)
    for i in r:
        results = i[0]
        if not results[1] == 'no_match':
            print '------------------------------'
            print results




