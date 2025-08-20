import logging
import os
from typing import Optional

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.mgmt.web import WebSiteManagementClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Function App
#api_gateway_bp = func.FunctionApp()
api_gateway_bp = func.Blueprint()

# Environment Configuration
class Config:
    SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
    TENANT_ID = os.getenv("AZURE_TENANT_ID")
    RESOURCE_GROUP = os.getenv("API_RESOURCE_GROUP")
    API_NAME = os.getenv("API_NAME")
    CLIENT_ID = os.getenv("AZURE_APP_CLIENT_ID")
    CLIENT_SECRET = os.getenv("AZURE_APP_CLIENT_SECRET")

# Initialize Azure credentials
def get_azure_credential() -> DefaultAzureCredential:
    return DefaultAzureCredential(
        managed_identity_client_id=Config.CLIENT_ID,
        exclude_environment_credential=True
    )

# WebSiteManagementClient factory
def get_web_client() -> WebSiteManagementClient:
    credential = get_azure_credential()
    return WebSiteManagementClient(credential, Config.SUBSCRIPTION_ID)

# Key retrieval service
def get_function_keys(function_name: str) -> Optional[dict]:
    try:
        web_client = get_web_client()
        keys = web_client.web_apps.list_function_keys(
            Config.RESOURCE_GROUP,
            Config.API_NAME,
            function_name
        )
        return keys.additional_properties if keys else {}
    except Exception as error:
        logging.error("Failed to fetch function keys: %s", error, exc_info=True)
        return None

# HTTP trigger function
@api_gateway_bp.route(route="keys/{function_name}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_function_keys_http(req: func.HttpRequest) -> func.HttpResponse:
    function_name = req.route_params.get('function_name')
    key_name = req.params.get('key_name', 'default')

    if not function_name:
        return func.HttpResponse("Function name is required", status_code=400)

    # Validate configuration
    required_vars = [Config.SUBSCRIPTION_ID, Config.RESOURCE_GROUP, 
                    Config.API_NAME, Config.CLIENT_ID, Config.CLIENT_SECRET]
    if not all(required_vars):
        return func.HttpResponse("Configuration is incomplete", status_code=500)

    # Retrieve keys
    keys = get_function_keys(function_name)
    if not keys:
        return func.HttpResponse("Function not found", status_code=404)

    # Return specific key
    if key_value := keys.get(key_name):
        return func.HttpResponse(key_value, mimetype='text/plain')
    
    return func.HttpResponse(f"Key '{key_name}' not found", status_code=404)