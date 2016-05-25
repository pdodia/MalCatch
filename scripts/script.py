import requests
import json
from bulk_entry import search_url, add_index, remove_index
import subprocess
from elasticsearch import Elasticsearch
import json
from pprint import pprint


## Global variables ##
global elastic_search_set
elastic_search_set = False


# Parse email for malicious url or file attachments #


# Search url in elastic search database #
def search_elasticSearch(url):
	#print(elastic_search_set)
	#print("in function")
	if(not elastic_search_set):
		add_index() ## Set up the elastic search database with malicious domain names ##
		global elastic_search_set
		elastic_search_set = True

	#print("after if")
	#print(elastic_search_set)
	malicious_url = search_url(url)
	print(malicious_url)

	return malicious_url #boolean that indicates if the given url was malicious or not

#Submit a url to cuckoo for analysis
def submit_url(givenurl):
	REST_URL = "http://localhost:8090/tasks/create/url"
	SAMPLE_URL = givenurl

	multipart_url = {"url": ("", SAMPLE_URL)}
	request = requests.post(REST_URL, files=multipart_url)

	# Add your code to error checking for request.status_code.
	print("request status:")
	print(request.status_code)

	json_decoder = json.JSONDecoder()
	task_id = json_decoder.decode(request.text)["task_id"]
	print("Successfully submitted url with task id:")
	print(task_id)

	# Check elastic search db for malicious behavior #
	return search_elasticSearch(givenurl)  #Returns True, if found malicious in DB, othw, False

#Submit a file to cuckoo for analysis
def submit_file(file_path):
	REST_URL = "http://localhost:8090/tasks/create/file"
	SAMPLE_FILE = file_path

	with open(SAMPLE_FILE, "rb") as sample:
	    multipart_file = {"file": ("temp_file_name", sample)}
	    request = requests.post(REST_URL, files=multipart_file)

	# Add your code to error checking for request.status_code.
	print("request status:")
	print(request.status_code)

	json_decoder = json.JSONDecoder()
	task_id = json_decoder.decode(request.text)["task_id"]

	# Add your code for error checking if task_id is None.
	print("Successfully submitted file with task id:")
	print(task_id)

	return

def getreport_results(taskid):
	with open('cuckoo-master/storage/analyses/'+str(taskid)+'/reports/report.json') as data_file:
		data = json.load(data_file)
	
	score = data["info"]["score"]
	host_ips = data["network"]["hosts"]
	dns_domains = data["network"]["dns"][0]["request"]
	#pprint(host_ips)
	#pprint(dns_domains)

	return (score,host_ips, dns_domains)

def check_dnslookup(dns_domains):
	#Check elastic search DB
	#Feed to VirusTotal and Malwar

	return

def check_hostips(host_ips):
	#Feed to VirusTotal and Malwar
	return


#########################################################
###### ----------------- MAIN ---------------------######
#########################################################

## --------SET UP------##

# --- Start elastic search ------#
#subprocess.call(["service", "elasticsearch", "start"])

#--- Run Elastic search ---- #
#print("started elastic search.....")
#res = requests.get('http://localhost:9200')
# Connect to a cluster #
#es = Elasticsearch([{'host': 'localhost', 'port': 9200}])


#-----Set the virtual network for tcp dump--------#
subprocess.call(["VBoxManage" ,"hostonlyif" ,"ipconfig" ,"vboxnet0" ,"--ip", "192.168.56.1", "--netmask", "255.255.255.0"])

# ----- Run CUCKOO REST API -------#
#subprocess.call("./Documents/cuckooProject/cuckoo-master/utils/api.py")

#----- Report Results ---------#
getreport_results(12)

#----- Submit URL/FILE ----------#
#print(elastic_search_set)
#submit_url("http://www.gptecno.it/")
#submit_file("/home/dodiap/Documents/cuckooProject/malware_files/ytisf-theZoo-9e11234/malwares/Source/Original/ZIB_Trojan/ZIB-Trojan/compileZIB.py")