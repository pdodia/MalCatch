import requests
import json
from bulk_entry import search_url, add_index, remove_index
from vt_ipscan import ipscan
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
	virustotal_total = 0
	virustotal_pos = 0

	## virus total report ##
	if data.has_key("virustotal"):
		if data["virustotal"].has_key("total"):
			virustotal_total = data["virustotal"]["total"]
			if data["virustotal"].has_key("summary"):
				if data["virustotal"]["summary"].has_key("positives"):
					virustotal_pos = data["virustotal"]["summary"]["positives"]
	
	#virustotal, total, summary, positives
	#pprint(host_ips)
	#pprint(dns_domains)
	#pprint(virustotal_total)

	return (score, host_ips, dns_domains, virustotal_total, virustotal_pos)

def check_dnslookup(dns_domains):
	#Check elastic search DB
	#Feed to VirusTotal and Malwar
	result = True #if domains referred during the analysis are malicious
	#pprint(dns_domains)

	for url in dns_domains:
		result = result and search_elasticSearch(url)

	return result

def check_hostips(host_ips):
	#Feed to VirusTotal and Malwar
	for ip in host_ips:
		vt_ipscan = ipscan(ip)
		pprint("from my script")
		pprint(vt_ipscan[0])
		pprint(vt_ipscan[1])
		
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
Malcatch = False #Final say on the url/file, True if deemed malicious, False otherwise
results = getreport_results(11)
score = results[0]
host_ips = results[1] 
dns_domains = results[2] 
virustotal_total = results[3] 
virustotal_pos = results[4]

# ----DNS domain analysis --------#
#pprint(virustotal_pos)
#pprint(virustotal_total)
vr = 100.0 * virustotal_pos/virustotal_total #if virus total positives are >50%, the link is tagged malicious
pprint(vr)
pprint(check_dnslookup(dns_domains) and vr >= 50.0)

# ------- Host ip analysis ---------#
check_hostips(host_ips)

#----- Submit URL/FILE ----------#
#print(elastic_search_(set)
#submit_url("http://www.gptecno.it/")
#submit_file("/home/dodiap/Documents/cuckooProject/malware_files/ytisf-theZoo-9e11234/malwares/Source/Original/ZIB_Trojan/ZIB-Trojan/compileZIB.py")