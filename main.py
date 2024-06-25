import hashlib
import requests

#check the SHA-256 hash from file
file_path =r"insert_file_path"
with open(file_path, "rb") as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()

#setup the URL and the API key of VirusTotal:
#I want to add more useful tools to it, so pending to modify
url = "https://www.virustotal.com/vtapi/v2/file/report"
api_key = "insert api"

#request parameters
parameters = {"apikey": api_key, "resource": file_hash}

#make the request through VirusTotal
response = resquests.get(url, parameters=parameters)

#verify the answer status
if response.status_code == 200:
    report = response.json()
    if report["response_code"] == 1:
        positives = report["positives"]
        total = report["total"]
        print(f'VirusTotal result for SHA-256 {file_hash} :')
        print(f'Detected: {positives}/{total}')
        scans = report["scans"]
        for scanner, result in scans.items():
            print(f"{scanner}:{result['result']}")
    else:
        print("the file was not scanned by VirusTotal")
else:
    print("Error in VirusTotal request")