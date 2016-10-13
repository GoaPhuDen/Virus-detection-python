#!/usr/local/bin/python3.5

import urllib.request
import json
import time
import smtplib
from email.mime.text import MIMEText
import ast
import random
import os
import socket


#example virus key
# sha1 virus: d1e986ea77c4e3ba69bb92d32c777f00
# sha256 novirus: c793e283146eababa2f035b2fee2369f165a376a4756c6bb23551d22076ee5d4

def result_function():
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    date = time.time()
    randomname = random.randint(1000, 99999)
    dir_ = os.path.dirname(os.path.realpath(__file__))
    is_sendMail = False
    serverip = str(socket.gethostbyname(socket.getfqdn()))
    with open(dir_ + '/txtSHA256.txt', 'r') as f:
        for sha1key in f.read().splitlines():
            dict = ast.literal_eval(sha1key)
            for key_file, key_value in dict.items():
                parameters = {"resource": key_value,
                              "apikey": "d31a91ec0297564515ccfb4b8d9a8bf749a3330fcbe19dab7b7b14f0a9d42108"}
                data = urllib.parse.urlencode(parameters)
                binary_data = data.encode('UTF-8')
                req = urllib.request.Request(url, binary_data)
                response = urllib.request.urlopen(req)
                json_ = response.read()
                result_ = json_.decode('UTF-8')
                json_convert = json.loads(result_)

                for antivirus in json_convert['scans'].keys():
                    virus = json_convert['scans'][antivirus]['detected']
                    if virus == True:
                        is_sendMail = True
                        with open(dir_ + '/txtEmail.txt', 'a+') as f1:
                            new_name = key_file + str(randomname)
                            os.rename(key_file, new_name)
                            f1.write("Server IP :" + " " + serverip + '\n')
                            f1.write("Virus Detected :  " + key_file + '\n')
                            f1.write(antivirus + " : " + str(json_convert['scans'][antivirus]['detected']) + '\n')
                            f1.write("More detail : " + "https://www.virustotal.com/vi/file/" + key_value + "/analysis/" + '\n')
                            break
                    else:
                        continue
                time.sleep(15)

        if(is_sendMail):
            is_sendMail = False
            with open(dir_ + '/txtEmail.txt', 'r') as f2:
                fromaddr = 'totalvirusnotify@gmail.com'
                toaddrs = 'thaopt@peacesoft.net'

                msg = MIMEText(f2.read())
                msg['Subject'] = 'VIRUS notify'
                msg['From'] = 'totalvirusnotify@gmail.com'
                msg['To'] = 'thaopt@peacesoft.net'

                username = 'totalvirusnotify@gmail.com'
                password = 'XBCsCKFaRciDww94E'

                server = smtplib.SMTP('smtp.gmail.com:587')
                server.starttls()
                server.login(username, password)
                server.sendmail(fromaddr, toaddrs, msg.as_string())
                server.quit()

#result_function()

