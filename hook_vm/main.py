import json
import os
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

import azure.functions as func
from azure.core.exceptions import ClientAuthenticationError
from azure.identity.aio import DefaultAzureCredential
from azure.storage.blob.aio import BlobServiceClient
from azure.storage.blob import generate_blob_sas, BlobSasPermissions
from azure.mgmt.storage import StorageManagementClient

logger = logging.getLogger(__name__)

class Config:
    SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
    TENANT_ID = os.getenv("AZURE_TENANT_ID")
    CLIENT_ID = os.getenv("AZURE_APP_CLIENT_ID")
    CLIENT_SECRET = os.getenv("AZURE_APP_CLIENT_SECRET")

class StorageManager:
    def __init__(self, credentials, subscription_id):
        self.storage_client = StorageManagementClient(credentials, subscription_id)

    async def create_storage_account(self, resource_group_name: str, storage_name: str, location: str) -> Dict[str, str]:
        storage_name = storage_name.lower()[:24]
        logger.info(f"Ensuring storage account '{storage_name}' in '{location}'...")
        try:
            # Wrap blocking SDK calls with asyncio.to_thread
            await asyncio.to_thread(
                self.storage_client.storage_accounts.get_properties,
                resource_group_name,
                storage_name,
            )
            logger.info(f"Storage account '{storage_name}' already exists.")
        except Exception:
            poller = await asyncio.to_thread(
                self.storage_client.storage_accounts.begin_create,
                resource_group_name,
                storage_name,
                {
                    "sku": {"name": "Standard_LRS"},
                    "kind": "StorageV2",
                    "location": location,
                    "enable_https_traffic_only": True,
                },
            )
            await asyncio.to_thread(poller.result)
            logger.info(f"Storage account '{storage_name}' created.")

        keys = await asyncio.to_thread(
            self.storage_client.storage_accounts.list_keys,
            resource_group_name,
            storage_name,
        )
        storage_key = keys.keys[0].value
        return {
            "url": f"https://{storage_name}.blob.core.windows.net",
            "name": storage_name,
            "key": storage_key,
        }

    async def delete_storage_account(self, resource_group_name: str, storage_name: str):
        storage_name = storage_name.lower()[:24]
        logger.info(f"Deleting storage account '{storage_name}'...")
        await asyncio.to_thread(
            self.storage_client.storage_accounts.delete,
            resource_group_name,
            storage_name,
        )
        logger.info(f"Storage account '{storage_name}' deleted.")

class BlobManager:
    @staticmethod
    async def ensure_container_exists(blob_service_client, container_name: str):
        container_client = blob_service_client.get_container_client(container_name)
        try:
            await container_client.create_container()
            logger.info(f"Created container '{container_name}'.")
        except Exception as e:
            logger.info(f"Container '{container_name}' already exists or failed: {e}")
        return container_client

    @staticmethod
    async def upload_blob_with_sas(
        blob_service_client,
        container_name: str,
        blob_name: str,
        data: str,
        storage_key: str,
        sas_expiry_hours: int = 1,
    ) -> str:
        await BlobManager.ensure_container_exists(blob_service_client, container_name)
        blob_client = blob_service_client.get_blob_client(container_name, blob_name)
        await blob_client.upload_blob(data, overwrite=True)
        logger.info(f"Uploaded blob '{blob_name}' to container '{container_name}'.")

        sas_token = generate_blob_sas(
            blob_service_client.account_name,
            container_name,
            blob_name,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + timedelta(hours=sas_expiry_hours),
            account_key=storage_key,
        )

        return f"https://{blob_service_client.account_name}.blob.core.windows.net/{container_name}/{blob_name}?{sas_token}"

# Request validation
def validate_request_params(req: func.HttpRequest) -> Optional[func.HttpResponse]:
    try:
        req_body = req.get_json()
    except ValueError:
        req_body = {}

    vm_name = req_body.get("vm_name") or req.params.get("vm_name")
    resource_group = req_body.get("resource_group") or req.params.get("resource_group")
    location = req_body.get("location") or req.params.get("location")
    status = req_body.get("status") or req.params.get("status")
    details = req_body.get("details") or req.params.get("details", {})

    missing_params = [p for p in ["vm_name", "resource_group", "location", "status"] if not locals()[p]]
    if missing_params:
        return func.HttpResponse(
            json.dumps({"error": f"Missing parameters: {', '.join(missing_params)}"}),
            status_code=400,
            mimetype="application/json",
        )

    return {
        "vm_name": vm_name,
        "resource_group": resource_group,
        "location": location,
        "status": status,
        "details": details,
    }

hook_vm_bp = func.Blueprint()

@hook_vm_bp.route(route="hook_vm", methods=["POST", "GET"], auth_level=func.AuthLevel.FUNCTION)
async def hook_vm(req: func.HttpRequest) -> func.HttpResponse:
    logger.info("Processing hook_vm request...")

    params = validate_request_params(req)
    if isinstance(params, func.HttpResponse):
        return params

    vm_name, resource_group, location, status, details = (
        params["vm_name"],
        params["resource_group"],
        params["location"],
        params["status"],
        params["details"],
    )

    if not all([Config.SUBSCRIPTION_ID, Config.CLIENT_ID, Config.CLIENT_SECRET, Config.TENANT_ID]):
        return func.HttpResponse(
            json.dumps({"error": "Missing required environment variables"}),
            status_code=500,
            mimetype="application/json",
        )

    try:
        credential = DefaultAzureCredential(managed_identity_client_id=Config.CLIENT_ID)
        storage_manager = StorageManager(credential, Config.SUBSCRIPTION_ID)

        storage_name = f"{vm_name}provision"
        storage_config = await storage_manager.create_storage_account(resource_group, storage_name, location)

        async with BlobServiceClient(
            account_url=storage_config["url"],
            credential=storage_config["key"],
        ) as blob_service_client:
            status_data = {
                "vm_name": vm_name,
                "status": status,
                "timestamp": datetime.utcnow().isoformat(),
                "details": details,
            }

            blob_url_with_sas = await BlobManager.upload_blob_with_sas(
                blob_service_client,
                "vm-webhook-json",
                f"{vm_name}-webhook.json",
                json.dumps(status_data),
                storage_config["key"],
                2,
            )

        if status in ("failed", "completed"):
            await storage_manager.delete_storage_account(resource_group, storage_name)

        return func.HttpResponse(
            json.dumps(
                {
                    "message": "Status updated",
                    "vm_name": vm_name,
                    "status": status,
                    "status_url": blob_url_with_sas,
                    "expiry_time": (datetime.utcnow() + timedelta(hours=2)).isoformat(),
                }
            ),
            status_code=200,
            mimetype="application/json",
        )

    except ClientAuthenticationError as auth_error:
        logger.error(f"Authentication error: {auth_error}")
        return func.HttpResponse(
            json.dumps({"error": "Authentication failed"}),
            status_code=401,
            mimetype="application/json",
        )
    except Exception as ex:
        logger.exception("Unhandled error:")
        return func.HttpResponse(
            json.dumps({"error": str(ex)}),
            status_code=500,
            mimetype="application/json",
        )