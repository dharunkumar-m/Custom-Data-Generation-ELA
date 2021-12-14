import json

from faker import Faker
from faker.providers import internet
from faker.providers import DynamicProvider

from random import randint 

fake = Faker()

#--------------------------------------------------------------------------------
    
bound_type_provider = DynamicProvider(
     provider_name="bound_type",
     elements=["inbound", "outbound"] )
     
fake.add_provider(bound_type_provider)
fake.add_provider(internet)

def generateCiscodata():
    record = {}
    remoteshost_ip = fake.ipv4_private()
    dest_ip = fake.ipv4_public()
    host = fake.ipv4_private()
    
    boundtype = fake.bound_type()
    protocol = "ICMP"
    
    record["COMMON_REPORT_NAME"] = "Traffic Allowed"
    record["TYPESEVERITY"] = randint(1, 10)
   
    record["IENAME"] = "Traffic Allowed"
    record["TYPESOURCE"] = "302020"
    record["FACILITY"] = "Local2"
    record["HOSTTYPE"] = "Cisco Device"
    record["PROTOCOL"] = protocol
    record["DESTINATION_IP"] = dest_ip
    record["TIME"] = int(fake.date_time_this_year().timestamp())
    record["REMOTEHOST"] = remoteshost_ip
    record["TYPEFACILITY"] = "ASA"
    record["HOSTNAME"] = host
    record["SOURCE_IP"] = remoteshost_ip
    record["SOURCE"] = "ASA-6-302020"
    record["TYPE"] = boundtype
    
    record["HOSTID"] = randint(1, 1000)
    record["SEVERITY"] = randint(1, 10)
    
    dest_ipport = dest_ip + "/" + str(randint(1, 65535))
    port = randint(1, 65535)
    remotesrc_ipport = remoteshost_ip + "/" + str(port)
    
    if boundtype == "inbound":
        name = " (" + fake.name() + ")"
        
        record["FIELD4"] = "0"
        record["MSGFIELD"] = "Built inbound " + protocol + " connection for faddr " + remotesrc_ipport + " gaddr " + dest_ipport + " laddr " + dest_ipport + name
    else:
        temp_ip = fake.ipv4_private() + "/" + str(randint(1, 65535))
        
        record["PORT"] = port
        record["MSGFIELD"] = "Built outbound " + protocol + " connection for faddr " + dest_ipport + " gaddr " + temp_ip + " laddr " + remotesrc_ipport
    
    return record
    
#--------------------------------------------------------------------------------  
windows_source_provider = DynamicProvider(
     provider_name="windows_source",
     elements=["nview", "igccservice", "gupdate", "Microsoft-Windows-Security-SPP"] )
     
fake.add_provider(windows_source_provider)

def generateWindowsdata():
    record = {}
  
    record["EVENTID"] =  randint(1, 16384)
    record["TIME"] = int(fake.date_time_this_year().timestamp())
    record["SOURCEPORT"] = randint(1, 65535)
    record["SUBHOSTTYPE"] = "WKS"
    record["SOURCE"] = fake.windows_source()
    record["TYPE"] = "Application"
    
    if record["SOURCE"] == "nview":
        record["MSGFIELD"] = "NvAPI function failed with: 'NVAPI_OUT_OF_MEMORY'"
    elif record["SOURCE"] == "gupdate":
        record["MSGFIELD"] = "Service started "
    elif record["SOURCE"] == "igccservice":
        record["MSGFIELD"] = "PowerEvent handled successfully by the service."
        
    
    record["SEVERITY"] = randint(1, 10)
    
    return record

#--------------------------------------------------------------------------------

for i in range(10):
    record = generateCiscodata()
    print(json.dumps(record, ensure_ascii=False))
    
for i in range(10):
    record = generateWindowsdata()
    print(json.dumps(record, ensure_ascii=False))

#--------------------------------------------------------------------------------
