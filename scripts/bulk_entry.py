####---------------------------------####
## Elastic Search: Internship Script 2 ##
## Name: Priyanka Dodia                ##
## University: CMUQ                    ##
## Department: Information Security    ##
####---------------------------------####

import requests
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from json import dumps
import urllib2
import re


########----------------------- HELPER FUNCTIONS -----------------------------#####
def readFromURL(url):
    content = []
    response = requests.get(url)
    content = response.content
    return content


def malwaredomainlist():
    url = "http://www.malwaredomainlist.com/hostslist/hosts.txt"
    # Fetch data from online doc
    content = readFromURL(url)
    content = content.split("127.0.0.1")
    content = content[1:]
    content = [re.sub('[\r\n]', '', domain) for domain in content]

    for i in range(0, len(content)):
        content[i] = '{"domain": "' + content[i] + '", "list_type": "domains"}'
        # print(content[i])

    return content


def sans():
    url = "https://isc.sans.edu/feeds/suspiciousdomains_High.txt"
    # Fetch data from online doc
    content = readFromURL(url)
    content = content.split("\t\n")
    size = len(content)
    content = content[1:size - 1]
    content = ['000007.ru'] + content

    for i in range(0, len(content)):
        content[i] = '{"domain": "' + content[i] + '", "list_type": "domains"}'
        # print(content[i])

    return content


def zeus():
    url = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"
    # Fetch data from online doc
    content = readFromURL(url)
    content = content.split("\n")
    content = content[6:len(content) - 1]

    for i in range(0, len(content)):
        content[i] = '{"domain": "' + content[i] + '", "list_type": "domains"}'
        # print(content[i])
    return content


def dga():
    url = "http://osint.bambenekconsulting.com/feeds/dga-feed.txt"
    # Fetch data from online doc
    content = readFromURL(url)
    content = re.compile('\n(.*?),Domain').findall(content)

    return content


def m_domains():
    url = "http://mirror1.malwaredomains.com/files/domains.txt"
    # Fetch data from online doc
    content = readFromURL(url)
    content = content.split("\n")
    content = content[4:]

    new_content = []
    for c in content:
        nc = c.split("\t")
        new_content = new_content + \
            ['{"domain": "' + nc[2] + '", "list_type": "domains"}']
        # print(nc)
        # print("\n")
        #new_content += [nc]

    # print(new_content)

    return new_content


def malcode_domains():
    url = "http://malc0de.com/bl/ZONES"
    # Fetch data from online doc
    content = readFromURL(url)
    content = content.split("\n")
    content = content[8:]
    new_content = []
    for c in content:
        nc = c.split("zone")
        if(len(nc) != 1):
            nc2 = nc[1]
            dom = re.compile(
                '(.*?) {type master; file "/etc/namedb/blockeddomain.hosts";};').findall(nc2)
            dom = dom[0]
            new_content += ['{"domain": ' + dom + ', "list_type": "domains"}']

    # print(new_content)
    return new_content

######### -------------------- ELASTIC SEARCH FUNCTIONALITY -------------------------#########
def remove_index(index_name):
    ## Delete pre existing index  ##
    es.indices.delete(index = index_name, ignore=400)
    print("index"+str(index_name)+"removed")
    return

def add_index():

    ## -------- CREATE NEW INDEX: black_domains -----------------##
    mapping = {
        "mappings": {
            "_default_": {
                "properties": {
                    "domain": {
                        "type": "string",
                        "index": "not_analyzed"
                    },
                    "list_type": {
                        "type": "string",
                        "index": "not_analyzed",
                    }
                }
            }
        }
    }


    ## Delete pre existing index 'black domains'  ##
    #es.indices.delete(index = 'black_domains', ignore=400)

    #print(es.search(index="black_domains")['hits']['total'])
    

    ## Create a new index 'black domains' ##
    es.indices.create(index="black_domains", ignore=400, body=mapping)


    ## ---------------------- DOWNLOAD MALICIOUS DOMAIN NAMES --------------------##
    print("Downloading data..........\n")
    ## 1. MalwareDomainList ##
    MDL = malwaredomainlist()

    ## 2. SANS  ##
    SANS = sans()

    ## 3. Zeus  ##
    ZEUS = zeus()

    ## 4. Bambinik consulting  ##
    #DGA = dga()

    ## 5. malwaredomains.com  ##
    mdomains = m_domains()

    ## 6. Malcode  ##
    malcode = malcode_domains()

    ## ------------------------ STORE DOMAIN NAMES IN ELASTIC SEARCH DATABASE ---------------##

    print("Indexing in Elastic search........\n")

    ## MDL ##
    action1 = []
    for value in MDL:
        content = {
                    "_index": "black_domains",
                    "_type": "MaliciousDomainList",
                    "_source": value }

        action1 = action1 + [content]

    #print(action1[0])
    #print("\n\n\n\n\n")
    bulk(client = es, actions = action1, index = "black_domains", doc_type = "MaliciousDomainList")

    ## SANS ##
    action2 = []
    for value in SANS:
        content = {
                    "_index": "black_domains",
                    "_type": "Sans",
                    "_source": value }
        action2 = action2 + [content]

    #print(action2[0])
    bulk(client = es, actions = action2, index = "black_domains", doc_type = "Sans")


    ## ZEUS ##
    action3 = []
    for value in ZEUS:
        content = {
                    "_index": "black_domains",
                    "_type": "Zeus",
                    "_source": value }
        action3 = action3 + [content]

    #print(action3[0])
    bulk(client = es, actions = action3, index = "black_domains", doc_type = "Zeus")


    # DGA ##
    #action4 = []
    #for value in DGA:  
    #content = {
    #                "_index": "black_domains",
    #                "_type": "MaliciousDomainList",
    #                "_source": value }
    #   json_value = '{"domain": "'+value+'", "list_type": "domains"}'
    #   content = '{ "index" : { "_index" : "black_domains", "_type" : "Dga"}},'+json_value
    #   action4 = action4 + [content]

    #print(action4[0])
    #bulk(client = es, actions = action4, index = "black_domains", doc_type = "Dga")


    ## MALWARE DOMAINS ##
    action5 = []
    for value in mdomains:
        content = {
                    "_index": "black_domains",
                    "_type": "MalwareDomains",
                    "_source": value }
        action5 = action5 + [content]

    #print(action5[0])
    bulk(client = es, actions = action5, index = "black_domains", doc_type = "MalwareDomains")

    ## MALCODE ##
    action6 = []
    for value in malcode:
        content = {
                    "_index": "black_domains",
                    "_type": "Malcode",
                    "_source": value }
        action6 = action6 + [content]

    #print(action6[0])
    bulk(client = es, actions = action6, index = "black_domains", doc_type = "Malcode")

    print("Added to the database")

    return


#Search url in db and returns true or false
def search_url(url):
    #print("searching url in database.....")
    #search3 = {"query": {"match": {"domain": "2biking.com"}}}
    search3 = {"query": {"match": {"domain": url}}}
    search_result = es.search(index='black_domains', body=search3)
    #x = dumps(search_result['aggregations'], indent=2)
    x = dumps(search_result['hits']['total'], indent=2)
    #print(x)
    if(x > 0):
        result = True
    else:
        result = False

    #print(result)
    return result



#### ------------------------------------------------------------------------------------------------####
## MAIN ##
#### ------------------------------------------------------------------------------------------------####
# Run Elastic search
print("started elastic search.....")
res = requests.get('http://localhost:9200')
# print(str(res.content)+"\n")

# Connect to a cluster
es = Elasticsearch([{'host': 'localhost', 'port': 9200}])

# add_index()
#print(search_url("2biking.com"))



## ---------------------------------------------------------------------------------------------------##













'''
## ---------------------------------- FILTERED SEARCH -----------------------------------#
## Search the database using filters ##
print("Searching ElasticSearch....")

#Simple aggregation
search_body = {
    "size": 0,
    "aggregations": {
        "Count_domain": {
            "terms": {
                "field": "domain"
            }
        }
    }
}

#Search by aggregating domain wise, providing count for domain in each doc type, filtering out a domain
#using 'exclude' reg ex
search_body2 = {
    "size": 0,
    "aggregations": {
        "domains": {
            "terms": {
                "field": "domain",
                "exclude": ".*.com"
            },
            "aggregations": {
                "feeds": {
                    "terms": {
                        "field": "_type"
                    }
                }
            }
        }
    }
}

#Search by aggregating for each domain based on doc type, filtering out 1 or more domains
# #{
#     "size": 0,
#     "query": {
#         "filtered": {
#             "filter": {
#                 "bool": {
#                     "must": [
#                         {"terms": {"domain": ["09cd.co.kr", "48wwuved42.ru"]}}
#                     ]
#                 }
#             }
#         }
#     }


search2 = {
    "size" : 0,
    "aggregations": {
        "domains": {
            "terms": {
                "field": "domain",
                "size": 0
            },
            "aggregations": {
                "feeds": {
                    "terms": {
                        "field": "_type",
                        "size": 0
                    }
                }
            }
        }
    }
}



RESULT: 
{
  "hits": [
    {
      "_score": 9.621372, 
      "_type": "MalwareDomains", 
      "_id": "AVTCr8tC4vwrxdvH-71-", 
      "_source": {
        "domain": "2biking.com", 
        "list_type": "domains"
      }, 
      "_index": "black_domains"
    }
  ], 
  "total": 1, 
  "max_score": 9.621372
}

'''


#f = open( 'esOutput.txt', 'w' )
#f.write(x)
#f.close()

'''
search3 = {"query": {"match": {"domain": "2biking.com"}}}
search_result = es.search(index='black_domains', body=search3)
#x = dumps(search_result['aggregations'], indent=2)
x = dumps(search_result['hits'], indent=2)
print(x)

'''