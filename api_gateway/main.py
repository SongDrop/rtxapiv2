import json
import logging
import os
from typing import Optional

import azure.functions as func
from azure.identity import ClientSecretCredential
from azure.mgmt.web import WebSiteManagementClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Function App
#api_gateway_bp = func.FunctionApp()
api_gateway_bp = func.Blueprint()


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
logger.info("Starting application initialization...")


# Environment Configuration
class Config:
    AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
    AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
    API_RESOURCE_GROUP = os.getenv("API_RESOURCE_GROUP")
    API_NAME = os.getenv("API_NAME")
    AZURE_APP_CLIENT_ID = os.getenv("AZURE_APP_CLIENT_ID")
    AZURE_APP_CLIENT_SECRET = os.getenv("AZURE_APP_CLIENT_SECRET")

def get_function_keys(function_name):
    try:
        credentials = ClientSecretCredential(
            client_id=Config.AZURE_APP_CLIENT_ID,
            client_secret=Config.AZURE_APP_CLIENT_SECRET,
            tenant_id=Config.AZURE_TENANT_ID
        )
        client = WebSiteManagementClient(credentials, Config.AZURE_SUBSCRIPTION_ID)

        keys = client.web_apps.list_function_keys(
            Config.API_RESOURCE_GROUP,
            Config.API_NAME,
            function_name
        )

        # keys is a dict-like object, get keys as dict
        function_keys = {}
        if keys:
            if hasattr(keys, 'additional_properties'):
                function_keys = keys.additional_properties
            else:
                function_keys = dict(keys)

        logger.info(f"Retrieved keys: {list(function_keys.keys())}")
        return function_keys

    except Exception as e:
        logger.error(f"Exception fetching keys for function '{function_name}': {e}", exc_info=True)
        return None

# HTTP trigger function
@api_gateway_bp.route(route="api_gateway", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def api_gateway(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
    except ValueError:
        req_body = {}

    # Accept function_name from query params or JSON body
    function_name = req_body.get('function_name') or req.params.get('function_name')
    key_name = req_body.get('key_name') or req.params.get('key_name') or 'default'  # default key if not provided
   
    # Check for missing parameters
    missing_params = []
    if not function_name:
        missing_params.append('function_name')

    if missing_params:
        error_msg = f"Missing parameters: {', '.join(missing_params)}"
        return func.HttpResponse(
            json.dumps({"error": error_msg}),
            status_code=400,
            mimetype="application/json"
        )
        
    # Validate configuration
    required_vars = [Config.AZURE_SUBSCRIPTION_ID, Config.API_RESOURCE_GROUP, 
                    Config.API_NAME, Config.AZURE_APP_CLIENT_ID, Config.AZURE_APP_CLIENT_SECRET]
    if not all(required_vars):
        return func.HttpResponse(
                json.dumps({"error": "Configuration is incomplete"}),
                status_code=500,
                mimetype="application/json"
            )

    # Retrieve keys
    keys = get_function_keys(function_name)
    if not keys:
        return func.HttpResponse(
                    json.dumps({"error": "Function not found"}),
                    status_code=404,
                    mimetype="application/json"
                )

    # Extract the single key requested
    key_value = keys.get(key_name)
    if not key_value:
        return func.HttpResponse(
            f"Key '{key_name}' not found for function '{function_name}'.",
            status_code=404
        )
    
    return func.HttpResponse(
        json.dumps(key_value),
        mimetype='application/json',
        status_code=200
    )