# The Below Code will generate 5 GB of Data

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

windows_type_provider = DynamicProvider(
     provider_name="windows_type",
     elements=["Application", "Security"] )
     
fake.add_provider(windows_type_provider)

security_msg = "An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tMS-23$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t5\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tYes\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tSYSTEM\r\n\tAccount Domain:\t\tNT AUTHORITY\r\n\tLogon ID:\t\t0x3E7\r\n\tLinked Logon ID:\t\t0x0\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x36c\r\n\tProcess Name:\t\tC:\\Windows\\System32\\services.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\t-\r\n\tSource Network Address:\t-\r\n\tSource Port:\t\t-\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tAdvapi  \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."

#--------------------------------------------------------------------------------

def generateWindowsdata():
    record = {}
  
    record["EVENTID"] =  randint(1, 16384)
    record["TIME"] = int(fake.date_time_this_year().timestamp())
    record["SOURCEPORT"] = randint(1, 65535)
    record["SUBHOSTTYPE"] = "WKS"
    record["TYPE"] = fake.windows_type()
    
    if record["TYPE"] == "Security":
      record["MSGFIELD"] = security_msg
      record["SOURCE"] = "Microsoft-Windows-Security-Auditing"
      record["RISK_LEVEL"] = "Low"
      
    else:
      record["SOURCE"] = fake.windows_source()
      if record["SOURCE"] == "nview":
        record["MSGFIELD"] = "NvAPI function failed with 'NVAPI_OUT_OF_MEMORY'"
      elif record["SOURCE"] == "gupdate":
        record["MSGFIELD"] = "Service started "
      elif record["SOURCE"] == "igccservice":
        record["MSGFIELD"] = "PowerEvent handled successfully by the service."
        
    record["SEVERITY"] = randint(1, 10)
    
    return record

#--------------------------------------------------------------------------------

for i in range(18000000):
    record = generateCiscodata()
    print(json.dumps(record, ensure_ascii=False))
    
for i in range(18000000):
    record = generateWindowsdata()
    print(json.dumps(record, ensure_ascii=False))

#--------------------------------------------------------------------------------
