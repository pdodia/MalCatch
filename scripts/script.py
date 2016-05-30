################################################################
## -----------------------------------------------------------##
## ---Developed by Priyanka Dodia ----------------------------##
## ---Dt: 1st May 2016 ---------------------------------------##
##----Note: Run your VM, cuckoo.py and------------------------## 
##--------- Elastic search (cmd: service elasticsearch start)-##
##--------- before running this script -----------------------##
#################################################################
import requests
import json
from bulk_entry import search_url, add_index, remove_index
from vt_ipscan import ipscan
import subprocess
from elasticsearch import Elasticsearch
import json
from pprint import pprint
import os.path


## Global variables ##
global elastic_search_set
elastic_search_set = True


# Parse email for malicious url or file attachments #
def beginES():
	if(not elastic_search_set):
		add_index() ## Set up the elastic search database with malicious domain names ##

# Search url in elastic search database #
def search_elasticSearch(url):
	malicious_url = search_url(url)
	#print(malicious_url)

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
	print("Successfully submitted url with task id: "+str(task_id))

	# Check elastic search db for malicious behavior #
	return 

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

	if(data["target"]["category"] == "url"):
		tested_url = data["target"]["url"]
	else:
		tested_url = False

	## virus total report ##
	if data.has_key("virustotal"):
		if data["virustotal"].has_key("total"):
			virustotal_total = data["virustotal"]["total"]
			if data["virustotal"].has_key("summary"):
				if data["virustotal"]["summary"].has_key("positives"):
					virustotal_pos = data["virustotal"]["summary"]["positives"]


	return (score, host_ips, dns_domains, virustotal_total, virustotal_pos, tested_url)

# def check_dnslookup(dns_domains):
# 	#Check elastic search DB
# 	#Feed to VirusTotal and Malwar
# 	result = True #if domains referred during the analysis are malicious
# 	#pprint(dns_domains)

# 	for url in dns_domains:
# 		result = result and search_elasticSearch(url)

# 	return result

def check_hostips(host_ips):
	pprint("Scanning host ips in VirusTotal......")
	#Feed to VirusTotal and Malwar
	for ip in host_ips:
		vt_ipscan = ipscan(ip)
		pprint("ip : "+str(ip)+ "  positives : "+str(vt_ipscan[0])+ "  total : "+str(vt_ipscan[1]))
		
	return


#########################################################
###### ----------------- MAIN ---------------------######
#########################################################
pprint("Welcome to MalCatch")
inp = input("   Enter 1 to setup elastic search database"+"\n"+
			   "Enter 2 to feed a url to Cuckoo Analyzer"+"\n"+
			   "Enter 3 to feed a file path to Cuckoo Analyzer"+"\n"+
			   "Enter 4 to check results"+"\n")
if(inp == 1):
	elastic_search_set = False
	beginES()
elif(inp == 2):
	#-----Set the virtual network for tcp dump--------#
	subprocess.call(["VBoxManage" ,"hostonlyif" ,"ipconfig" ,"vboxnet0" ,"--ip", "192.168.56.1", "--netmask", "255.255.255.0"])
	givenurl = raw_input("Enter url\n")
	#----- Submit URL CUCKOO----------#
	#angryshippflyforok.su
	#anlacviettravel.com.vn
	submit_url(givenurl)	
elif(inp == 3):
	#-----Set the virtual network for tcp dump--------#
	subprocess.call(["VBoxManage" ,"hostonlyif" ,"ipconfig" ,"vboxnet0" ,"--ip", "192.168.56.1", "--netmask", "255.255.255.0"])
	
	givenpath = raw_input("Enter path to file\n")
	#----- Submit FILE CUCKOO ---------#
	#"/home/dodiap/Documents/cuckooProject/malware_files/ytisf-theZoo-9e11234/malwares/Source/Original/ZIB_Trojan/ZIB-Trojan/compileZIB.py"
	submit_file(givenpath)
elif(inp == 4):
	#----- Report Results ---------------#
	taskid = input("Enter taskid :  \n (Warning: Throws error if cuckoo report with taskid doesn't exist already.\n Run an analysis(options 2/3) first to use this feature)\n")

	Malcatch = False #Final say on the url/file, True if deemed malicious, False otherwise
	results = getreport_results(taskid)
	score = results[0]
	host_ips = results[1] 
	dns_domains = results[2] 
	virustotal_total = results[3] 
	virustotal_pos = results[4]
	task_url = results[5]

	#-----Check ElasticSearch if url --------#
	if(not task_url == False):
		dnslookup_res = search_elasticSearch(task_url)  #Returns True, if found malicious in DB, othw, False
		pprint(str("Submitted url marked malicious in elastic search :  ")+ str(dnslookup_res))
	else:
		pprint("Marking files malicious by MalCatch, still underdevelopment")
		pprint("Cuckoo analyzer score : "+str(score))

	# -----Built in VirusTotal in Cuckoo --------#
	vr = 100.0 * virustotal_pos/virustotal_total #if virus total positives are >50%, the link is tagged malicious
	pprint(str("Cuckoo Virus Total positives(in %) :   ")+str(vr))

	########Malcatch = dnslookup_res and vr >= 50.0  

	# ------- Host ip analysis ---------#
	check_hostips(host_ips)

else:
	pprint("Please rerun the script and enter a valid no. as instructed above")

## --------AUTO INITIAL SET UP------##

# --- Start elastic search ------#
#subprocess.call(["service", "elasticsearch", "start"])

#--- Run Elastic search ---- #
#print("started elastic search.....")
#res = requests.get('http://localhost:9200')
# Connect to a cluster #
#es = Elasticsearch([{'host': 'localhost', 'port': 9200}])


# ----- Run CUCKOO REST API -------#
#subprocess.call("./Documents/cuckooProject/cuckoo-master/utils/api.py")








