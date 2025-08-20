import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

import azure.functions as func
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from azure.mgmt.storage import StorageManagementClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Function App
#app = func.FunctionApp()

# Configure logging
logger = logging.getLogger(__name__)

# Configuration class
class Config:
    SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
    TENANT_ID = os.getenv("AZURE_TENANT_ID")
    CLIENT_ID = os.getenv("AZURE_APP_CLIENT_ID")
    CLIENT_SECRET = os.getenv("AZURE_APP_CLIENT_SECRET")

# Storage account management
class StorageManager:
    def __init__(self, credentials, subscription_id):
        self.storage_client = StorageManagementClient(credentials, subscription_id)
        self.credentials = credentials
        
    def create_storage_account(self, resource_group_name: str, storage_name: str, location: str) -> Dict[str, str]:
        logger.info(f"Creating storage account '{storage_name}' in '{location}'...")
        
        try:
            # Check if storage account exists
            self.storage_client.storage_accounts.get_properties(resource_group_name, storage_name)
            logger.info(f"Storage account '{storage_name}' already exists.")
        except Exception:
            # Create new storage account
            poller = self.storage_client.storage_accounts.begin_create(
                resource_group_name,
                storage_name,
                {
                    "sku": {"name": "Standard_LRS"},
                    "kind": "StorageV2",
                    "location": location,
                    "enable_https_traffic_only": True
                }
            )
            poller.result()
            logger.info(f"Storage account '{storage_name}' created.")

        # Get storage account keys
        keys = self.storage_client.storage_accounts.list_keys(resource_group_name, storage_name)
        storage_key = keys.keys[0].value
        
        return {
            "url": f"https://{storage_name}.blob.core.windows.net",
            "name": storage_name,
            "key": storage_key
        }
    
    def delete_storage_account(self, resource_group_name: str, storage_name: str):
        logger.info(f"Deleting storage account '{storage_name}'...")
        self.storage_client.storage_accounts.delete(resource_group_name, storage_name)
        logger.info(f"Storage account '{storage_name}' deleted.")

# Blob storage operations
class BlobManager:
    @staticmethod
    def ensure_container_exists(blob_service_client, container_name: str):
        logger.info(f"Checking container '{container_name}'.")
        container_client = blob_service_client.get_container_client(container_name)
        try:
            container_client.create_container()
            logger.info(f"Created container '{container_name}'.")
        except Exception:
            logger.info(f"Container '{container_name}' already exists.")
        return container_client

    @staticmethod
    def upload_blob_with_sas(
        blob_service_client, 
        container_name: str, 
        blob_name: str, 
        data: str, 
        storage_key: str,
        sas_expiry_hours: int = 1
    ) -> str:
        logger.info(f"Uploading blob '{blob_name}' to container '{container_name}'.")
        
        # Ensure container exists
        BlobManager.ensure_container_exists(blob_service_client, container_name)
        
        # Upload blob
        blob_client = blob_service_client.get_blob_client(container_name, blob_name)
        blob_client.upload_blob(data, overwrite=True)
        logger.info(f"Uploaded blob '{blob_name}' to container '{container_name}'.")
        
        # Generate SAS token
        sas_token = generate_blob_sas(
            blob_service_client.account_name,
            container_name,
            blob_name,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + timedelta(hours=sas_expiry_hours),
            account_key=storage_key
        )
        
        # Construct URL with SAS token
        blob_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{container_name}/{blob_name}"
        blob_url_with_sas = f"{blob_url}?{sas_token}"
        
        logger.info(f"SAS URL generated for blob '{blob_name}'.")
        return blob_url_with_sas

# Request validation
def validate_request_params(req: func.HttpRequest) -> Optional[func.HttpResponse]:
    """Validate required parameters in the request"""
    try:
        req_body = req.get_json()
    except ValueError:
        req_body = {}

    # Get parameters from body or query string
    vm_name = req_body.get('vm_name') or req.params.get('vm_name')
    resource_group = req_body.get('resource_group') or req.params.get('resource_group')
    location = req_body.get('location') or req.params.get('location')
    status = req_body.get('status') or req.params.get('status')
    details = req_body.get('details') or req.params.get('details', {})

    # Check for missing parameters
    missing_params = []
    if not vm_name:
        missing_params.append('vm_name')
    if not resource_group:
        missing_params.append('resource_group')
    if not location:
        missing_params.append('location')
    if not status:
        missing_params.append('status')

    if missing_params:
        error_msg = f"Missing parameters: {', '.join(missing_params)}"
        logger.error(error_msg)
        return func.HttpResponse(
            json.dumps({"error": error_msg}),
            status_code=400,
            mimetype="application/json"
        )
    
    return {
        "vm_name": vm_name,
        "resource_group": resource_group,
        "location": location,
        "status": status,
        "details": details
    }

# HTTP trigger function
hook_vm_bp = func.Blueprint()

@hook_vm_bp.route(route="hook_vm", methods=["POST", "GET"], auth_level=func.AuthLevel.FUNCTION)
async def hook_vm(req: func.HttpRequest) -> func.HttpResponse:
    logger.info('Processing hook_vm request...')
    
    # Validate request parameters
    params = validate_request_params(req)
    if isinstance(params, func.HttpResponse):
        return params
    
    vm_name = params["vm_name"]
    resource_group = params["resource_group"]
    location = params["location"]
    status = params["status"]
    details = params["details"]
    
    # Validate configuration
    if not all([Config.SUBSCRIPTION_ID, Config.CLIENT_ID, Config.CLIENT_SECRET, Config.TENANT_ID]):
        error_msg = "Missing required environment variables"
        logger.error(error_msg)
        return func.HttpResponse(
            json.dumps({"error": error_msg}),
            status_code=500,
            mimetype="application/json"
        )
    
    try:
        # Authenticate with Azure
        credential = DefaultAzureCredential(
            managed_identity_client_id=Config.CLIENT_ID,
            exclude_environment_credential=False
        )
        
        # Initialize managers
        storage_manager = StorageManager(credential, Config.SUBSCRIPTION_ID)
        storage_config = storage_manager.create_storage_account(
            resource_group, 
            f"{vm_name}provision", 
            location
        )
        
        # Create blob service client
        blob_service_client = BlobServiceClient(
            account_url=storage_config["url"], 
            credential=credential
        )
        
        # Prepare status data
        status_data = {
            "vm_name": vm_name,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        }
        
        # Upload status to blob storage
        blob_url_with_sas = BlobManager.upload_blob_with_sas(
            blob_service_client,
            'vm-webhook-json',
            f"{vm_name}-webhook.json",
            json.dumps(status_data),
            storage_config["key"],
            2  # 2 hour expiry
        )
        
        logger.info(f"Updated json status to Blob Storage: {blob_url_with_sas}")
        
        # Clean up storage account for terminal states
        if status in ("failed", "completed"):
            storage_manager.delete_storage_account(resource_group, f"{vm_name}provision")
            logger.info(f"Deleted storage account '{vm_name}provision'.")
        
        # Prepare response
        result = {
            "message": "Status updated",
            "vm_name": vm_name,
            "status": status,
            "status_url": blob_url_with_sas,
            "expiry_time": (datetime.utcnow() + timedelta(hours=2)).isoformat()
        }
        
        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json"
        )
        
    except ClientAuthenticationError as auth_error:
        logger.error(f"Authentication error: {auth_error}")
        return func.HttpResponse(
            json.dumps({"error": "Authentication failed"}),
            status_code=401,
            mimetype="application/json"
        )
    except Exception as ex:
        logger.exception("Unhandled error:")
        return func.HttpResponse(
            json.dumps({"error": str(ex)}),
            status_code=500,
            mimetype="application/json"
        )