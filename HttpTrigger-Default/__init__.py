import azure.functions as func
import logging
import os
import requests
import json
from azure.storage.blob import BlobClient,BlobServiceClient
from configparser import ConfigParser
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    
    schema=""
    name = req.params.get('name')
    if not name:
        try:
            null = ""
            req_body = req.get_json()
            schema = req_body
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    configur = ConfigParser()
    configur.read('config.ini')
        
    workspace_id = configur.get('azure-credentials','workspace_id')
    client_id = configur.get('azure-credentials','client_id')    
    client_secret = configur.get('azure-credentials','client_secret')    
    tenant_id = configur.get('azure-credentials','tenant_id')    
    

    credential = ClientSecretCredential(tenant_id,client_id,client_secret)
    vault_url= "https://campbell-keyvault.vault.azure.net/"
    client = SecretClient(vault_url=vault_url, credential=credential)

    
    account_key= client.get_secret("accountkey").value #'d/0RHq4Mchnf4PusVapI0UOsPx7BRQkf8Pynr+iizz6h3ZKhCHrc/YGgyL+HmtXh8P3Ej7gCTcVz+ASti6cb+w==' 
    
    
    resource = 'https://api.loganalytics.io'
    

    # Obtain an access token using client credentials
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/token'
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': resource
    }
    token_response = requests.post(token_url, data=token_data)
    access_token = token_response.json().get('access_token')

    logging.info("token_response")
    logging.info(token_response)

    logging.info("access_token")
    logging.info(access_token)

    # Query parameters
    query = ""

    # API endpoint for querying Log Analytics data
    query_url = schema['data']['alertContext']['condition']['allOf'][0]['linkToFilteredSearchResultsAPI']
    
    logging.info("query_url")
    logging.info(query_url)
    
    headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
    }
    
    query_data = {    'query': query    }

    # Make the query request
    response = requests.get(query_url, headers=headers, data=json.dumps(query_data))
    
    logging.info("Response - API Data extraction")
    logging.info(response)
    
    if response.status_code == 200:
        query_result = response.json()
    
        logging.info("API Result")
        logging.info(query_result)
    
        alert_result = query_result['tables'][0]['rows'][0]

        print("API data extracted!")

        columnnames=['category',
        'subcategory',
        'contact_type',
        'Application',
        'Resource',
        'ResourceGroup',
        'dxcManaged',
        'dxcMonitored',
        'pipelineName',
        'Status', 
        'TimeGenerated',
        'SubscriptionId',
        'Category',
        'Level',
        'OperationName',
        'Error_Message',       
        'ResourceId', 
        'AppSupportTeam',
        'AppOwner',
        'Environment',
        "ExperimentName",
        "JobName",
        "joburl"]

        logging.info(json.dumps(query_result, indent=50))
        
        #account_url="https://"+alert_result[-2]+".blob.core.windows.net"
        account_url="https://wpdxcsandboxdevml.blob.core.windows.net"
        BLOBNAME="ExperimentRun/dcid."+alert_result[-2]+"/user_logs/std_log.txt"
        CONTAINERNAME="azureml"

        logging.info("account_url")
        logging.info(account_url)

        logging.info("blobname")
        logging.info(BLOBNAME)

        """
        blob_service_client_instance = BlobServiceClient(account_url="https://"+alert_result[-2]+".blob.core.windows.net",
                    credential=account_key)
        """
        blob_service_client_instance = BlobServiceClient(account_url=account_url,credential=account_key)
        
                    
        blob_client_instance = blob_service_client_instance.get_blob_client(CONTAINERNAME, BLOBNAME, snapshot=None)

        LOCALFILENAME= "example.txt"
        with open(os.getcwd()+"\\"+LOCALFILENAME, "wb") as my_blob:
            blob_data = blob_client_instance.download_blob()
            blob_data.readinto(my_blob)
        
        filename=os.getcwd()+"\\"+"example.txt"
        with open(filename) as f:
            contents = f.readlines()
        
        error_contents = []
        for i in range(len(contents)):
            if "Error" in contents[i]:
                error_contents.append(contents[i])

        logging.info("error_contents")
        logging.info(error_contents)
        #error_contents = ["To Be Included"]
        
        columnvalues=[error_contents[-1]]+alert_result
        columnnames=["error.logfile"]+columnnames

        description_content = dict(zip(columnnames, columnvalues))
        
        print("ML Log  data extracted!")
        logging.info(description_content)
    
        ## Create Servicenow ticket 
               
        servicenow_url =  client.get_secret("servicenowurl").value
        servicenow_user = client.get_secret("servicenowusername").value
        servicenow_password = client.get_secret("servicenowpassword").value
        
        
        payload = {
                "short_description": schema['data']['essentials']['alertRule'],
                "description": description_content,
                "contact_type":'monitoring',
                "caller_id":'azure.ml.monitoring',
                "urgency": '3 - Medium',
                "impact": '3 - Medium',
                "cmdb_ci":'DA_AML_CAPS',
                "u_task_behalf_of":'Parimala Killada',
                "assignment_group":'DXC_Application_Analytics',
                "category":'Application',
                "subcategory":'Incident/Break Fix'
                
                
            }

        headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

        response = requests.post(servicenow_url, json=payload, auth=(servicenow_user, servicenow_password), headers=headers)

        if response.status_code == 201:
           logging.info(f"Successfully created ServiceNow ticket. Status code: {response.status_code}")
           return func.HttpResponse("ServiceNow ticket created successfully.", status_code=200)
        else:
            logging.info(f"Failed to create ServiceNow ticket. Status code: {response.status_code}")
            return func.HttpResponse(f"Failed to create ServiceNow ticket. Status code: {response.status_code}", status_code=500)
    
    