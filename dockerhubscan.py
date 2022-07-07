from modulefinder import AddPackagePath
import os
import json
from datetime import datetime
from pydoc import doc
from tabulate import tabulate
from shlex import quote
import re
import requests

def createdir():
    #create directory
    now = datetime.now()
    current_time = now.strftime("%H%M%S")
    filename = "tempdir"+current_time
    path = os.getcwd()+"/tempdir"+current_time
    print(path)
    os.makedirs(path)
    return path

def dockerpull(image):
    #pull docker image
    os.system("docker pull "+image)

def dockersave(image, i, path):
    #save docker image
    os.system("docker save "+image+" -o "+path+"/"+i)

def containerscan(i, path):
    #scan for containers
    #Cloudguard Shiftleft requires CHKP_CLOUDGUARD_ID and CHKP_CLOUDGUARD_SECRET variables to set in the envrionment
    os.system("shiftleft image-scan -r -2000 -e <<Shiftleft environment ID>> -i "+path+"/"+i+" -j > "+path+"/"+i+".json")

def cleandir(path):
    #clean up directory
    os.system("rm -rf "+path)

def dockersearch2(searchterm):
    #search for docker images
    text2 = re.search(r'(.*):', searchterm)
    URL = "https://hub.docker.com/v2/repositories/library/"+text2.group(1)
    r = requests.get(url = URL)
    string=r.text
    jsonstring=json.loads(string)
    return(jsonstring["pull_count"])

def countwordinstring(string, word):
    count = 0
    for i in range(len(string)):
        if string[i:i+len(word)] == word:
            count += 1
    return count

  #A list of top dockerhub images, in no particular order
listofimages = ["ubuntu:latest", "centos:latest", "nginx:latest", "redis:latest", "node:latest", "postgres:latest", "mysql:latest", "mongo:latest", "debian:latest"]

searchout = []
mainpath = createdir()
i = 0
for image in listofimages:
    list1 = []
    i = i + 1
    f = dockersearch2(image)
    dockerpull(image)
    dockersave(image, str(i), mainpath)
    containerscan(str(i), mainpath)
    jsonfile = json.load(open(mainpath+"/"+str(i)+".json"))
    file2 = jsonfile['assessment-rules']
    critical = json.dumps(file2[2])
    high = json.dumps(file2[0])
    mid = json.dumps(file2[1])
    metadata = jsonfile['metadata']
    list1.append(metadata["project-name"])
    list1.append(f)
    criticalcount = countwordinstring(critical, 'findings')
    list1.append(criticalcount)
    highcount = countwordinstring(high, 'findings')
    list1.append(highcount)
    midcount = countwordinstring(mid, 'findings')
    list1.append(midcount)
    print(list1)
    searchout.append(list1)

cleandir(mainpath)
print(tabulate(searchout, headers=["Name", "Pull Count", "Critical Vulns", "High Vulns", "Medium Vulns"],tablefmt="grid"))
