import json
import datetime
import toml
from quickchart  import QuickChart # sudo pip3 install quickchart.io
from docxtpl import DocxTemplate   #pip3 install docxtpl
from docx.shared import Mm
from docxtpl import InlineImage
import requests
import toml
import pandas as pd
import os
import yaml
import glob

Banner = """                                                  
 __  __ _                     __ _     ___          _   _          _ 
|  \/  (_)__ _ _ ___ ___ ___ / _| |_  / __| ___ _ _| |_(_)_ _  ___| |
| |\/| | / _| '_/ _ (_-</ _ \  _|  _| \__ \/ -_) ' \  _| | ' \/ -_) |
|_|_ |_|_\__|_| \___/__/\___/_|  \__| |___/\___|_||_\__|_|_||_\___|_|
/ __|/ _ \ / __|  / _ \ _ __| |_(_)_ __ (_)_____ _| |_(_)___ _ _     
\__ \ (_) | (__  | (_) | '_ \  _| | '  \| |_ / _` |  _| / _ \ ' \    
|___/\___/ \___|  \___/| .__/\__|_|_|_|_|_/__\__,_|\__|_\___/_||_|   
                       |_|                                                        
        Microsoft Sentinel SOC Optimization TTP Aligner - 2025
"""

print(Banner)
# Load Configuration File
config = toml.load('Config/Config.toml')

Client_ID =  config['Client_ID']
Client_Secret =  config['Client_Secret']
EntraID_Tenant =  config['EntraID_Tenant']
Workspace =  config['Workspace']
WorkspaceID = config['WorkspaceID']
subscriptionID =  config['subscriptionID']
ResourceGroup = config['ResourceGroup']

Local_Path = "Resources/sigma-master/rules/"

# Get Microsoft Sentinel Access Token
def GetMicrosoftSentinelToken(Client_ID, Client_Secret, EntraID_Tenant):
    Url = "https://login.microsoftonline.com/"+EntraID_Tenant+"/oauth2/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload='grant_type=client_credentials&client_id='+ Client_ID+'&resource=https%3A%2F%2Fmanagement.azure.com&client_secret='+Client_Secret
    response = requests.post(Url, headers=headers, data=payload).json()
    Access_Token = response["access_token"]
    print("[+] Access Token Received Successfully")
    print("[+] Connecting to Microsoft Sentinel ...")
    return Access_Token


def GetAtomicRedTeamTests():
    Url = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/master/atomics/Indexes/Attack-Navigator-Layers/art-navigator-layer.json"
    response = requests.get(Url).json()
    return response

def GetSigmaRules():
    SGM = []
    if os.path.isdir("Resources/sigma-master/") == False: # ! Check if Sigma Rules exist 
        print("[+] Downloading SIGMA Rules ...")
        Command2 = "git clone https://github.com/SigmaHQ/sigma Resources/sigma-master  > /dev/null 2>&1"
        os.system(Command2) # Clone Sigma Rules
    else:
        print("[+] SIGMA Rules already exists")
    for rule in glob.iglob(Local_Path  + '**/**', recursive=True):
        if rule.endswith('.yml'): # Check if file is a yaml file
            with open(rule,'r',encoding='utf-8') as q: #errors='ignore'
                try:
                    yaml_query = yaml.load(q, Loader=yaml.FullLoader)
                    for j in range(len(yaml_query["tags"])):
                        #print("[+] "+ (str(yaml_query["tags"][j]).replace("t","T").replace("aTTack.","")) +" "+str(rule))
                        SGM.append({"Technique":str(yaml_query["tags"][j]).replace("t","T").replace("aTTack.",""),"Rule":str(rule)})    
                except:
                    pass
    return SGM


# Get Sigma Rules
print("[+] Extracting Sigma Rules ...")
SigmaRulesList = GetSigmaRules()
print(len(SigmaRulesList), "Sigma Rules Extracted Successfully")


# Get Atomic Red Team Tests
print("[+] Extracting Atomic Red Team Tests ...")
GetAtomicTests = GetAtomicRedTeamTests()
StoreARTTests = []
for test in GetAtomicTests['techniques']:
        Technique = test['techniqueID']
        URL = test['links'][0]['url']
        StoreARTTests.append({"Technique": Technique, "URL": URL})

print(len(StoreARTTests), "Atomic Red Team Tests Extracted Successfully")

# Print access token
Access_Token = GetMicrosoftSentinelToken(Client_ID, Client_Secret, EntraID_Tenant)

# Get Microsoft Sentinel SOC Optimization Recommendations
def GetMicrosoftSentinelRecommendations(Access_Token, Subscription, ResourceGroup, Workspace):
    Url = "https://management.azure.com/subscriptions/"+Subscription+"/resourceGroups/"+ResourceGroup+"/providers/Microsoft.OperationalInsights/workspaces/"+Workspace+"/providers/Microsoft.SecurityInsights/recommendations?api-version=2024-10-01-preview"
    Auth = 'Bearer '+Access_Token
    headers = {
      'Authorization': Auth ,
      'Content-Type': 'application/json',
    }
    response = requests.get(Url, headers=headers).json()
    print("[+] Microsoft Sentinel SOC Optimization Recommendations Received Successfully")
    return response


print("[+] Extracting Microsoft Sentinel SOC Optimization Recommendations ...")
Recommendations = GetMicrosoftSentinelRecommendations(Access_Token, subscriptionID,ResourceGroup, Workspace)


Optimizations = []
TTPs = []
AtomicTests = []
SigmaRules = []
for optimization in Recommendations['value']:
    Title = optimization['properties']['title']
    print("[+] SOC Optimization: ", Title)
    State = optimization['properties']['state']
    CreationTime = optimization['properties']['creationTimeUtc']
    if State in ['Active', 'InProgress']:
        try:
            Tactics = optimization['properties']['suggestions'][0]['additionalProperties']['Tactics']
            # Convert Tactics to json
            Tactics = json.loads(Tactics)
            Techniques = []
            for tactic in Tactics:
                print("Tactics: ", tactic['Name'])
                # print Techniques
                tactic_techniques = tactic['Techniques']
                for technique in tactic_techniques:
                    print("Technique: ", technique['Name'])
                    Techniques.append(technique['Name'])
                    TTPs.append({"Optimization": Title, "Tactic": tactic['Name'], "Technique": technique['Name']})
            Layer_Template = {
                "description": str(Title)+" Techniques",
                "name": str(Title)+" Techniques",
                "domain": "mitre-enterprise",
                "version": "4.5",
                "techniques": 
                    [{  "techniqueID": technique, "color": "#5df542"  } for technique in Techniques] 
                ,
                "gradient": {
                    "colors": [
                        "#ffffff",
                        "#5df542"
                    ],
                    "minValue": 0,
                    "maxValue": 1
                },
                "legendItems": [
                    {
                        "label": str(Title)+" Techniques",
                        "color": "#ff0000"
                    }
                ]
            }
            json_data = json.dumps(Layer_Template)
            with open("SOCOptimization_"+str(Title)+"_Coverage.json", "w") as file:
                json.dump(Layer_Template, file)
            print("[+] SOC Optimization Techniques Coverage JSON Files Generated Successfully")
            print("[+] Generating Atomic Red Team Tests for SOC Optimization Techniques ...")
            for TTP in Techniques:
                print("[+] Generating Atomic Red Team Tests for Technique: ", TTP)
                for test in StoreARTTests:
                    if str(test['Technique']).lower() == TTP.lower().split(".")[0]:
                        AtomicTests.append({"Optimization": Title, "Technique": TTP, "URL": test['URL']})
            print("[+] Generating Sigma Rules for SOC Optimization Techniques ...")
            # Generate Sigma Rules
            for TTP in Techniques:
                #print("[+] Generating Sigma Rules for Technique: ", TTP)
                for rule in SigmaRulesList:
                    if str(rule['Technique']).lower() == TTP.lower().split(".")[0]:
                        #print("[+] Sigma Rule for Technique: ", TTP)
                        SigmaRules.append({"Optimization": Title, "Technique": TTP, "Rule": rule['Rule']})

        except:
            Tactics = "No Tactics were found"
    else:
        print("[-] SOC Optimization is not Active")
        Tactics = "[-] No Tactics were found"


# Export Atomic Red Team Tests to csv
df = pd.DataFrame(AtomicTests)
df.to_csv('AtomicRedTeamTests.csv', index=False)
print("[+] Atomic Red Team Tests Exported Successfully")


# Export Sigma Rules to csv
df = pd.DataFrame(SigmaRules)
df.to_csv('SigmaRules.csv', index=False)
print("[+] Sigma Rules Exported Successfully")




