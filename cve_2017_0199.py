"""
Extracts encoded URLs from documents exploiting CVE-2017-0199

Sample file:
2cfcf74df127a3cf8fe167663ee331d9a751f18932eec4ad7aa9555805a3980b

"""


import os


filename = "2cfcf74df127a3cf8fe167663ee331d9a751f18932eec4ad7aa9555805a3980b"


f_in = open(filename)
data = f_in.read()
data = str(data)
f_in.close()


def find_cve2017_0199_url(data):
        try:
            if '68007400740070003a002f002f' not in data:
                print 'URL not found'

            test = data.split('68007400740070003a002f002f')[1]            
            test = test.replace('\r', '').replace('\n', '').replace('=','').replace(' ','').replace('\t','')
            test = test[:200]#allow for 200 character buffer

            hex_preproc = []
            for i in xrange(0, len(test), 2):
                op, code = test[i:i+2]
                byte = str(op)+str(code)
                t = byte.decode('hex')
                ord_check = ord(t)
                if ord_check != 0 and ord_check <= 127:
                    hex_preproc.append(t)

            url = ''.join(hex_preproc)
            url = url.split('X;')[0]

            return url
        except Exception, e:
            print e

url = find_cve2017_0199_url(data)
print 'URL:',url

