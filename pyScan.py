__author__ = "TheThao Pham"
__copyright__ = "Copyright 2016, TheThao Pham"
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "VanDuc Phan"
__email__ = "thaoptvn89@gmail.com"
__status__ = "Prototype"


import postfile
import json
import time
import pyResult
import os


f0 = open('txtEmail.txt', 'w')
f0.close()

os.system('./shFind.sh')

f1 = open('txtSHA256.txt', 'w')
with open('txtListFile.txt', 'r', encoding='utf-8') as f:
    for content in f.read().splitlines():
        temp_dict = {}
        host = "www.virustotal.com"
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", "d31a91ec0297564515ccfb4b8d9a8bf749a3330fcbe19dab7b7b14f0a9d42108")]
        file_to_send = open(str(content), "r", errors='ignore').read()
        files = [("file", str(content), file_to_send)]
        json_ = postfile.post_multipart(host, selector, fields, files)
        # json_convert : SHA256 result
        json_convert_ = json.loads(json_)
        temp_dict[content] = json_convert_['sha256']
        f1.write(str(temp_dict) + '\n')
        time.sleep(1)
f1.close()

pyResult.result_function()



