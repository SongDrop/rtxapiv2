import azure.functions as func
import datetime
import json
import logging
from hook_vm.main import hook_vm_bp
from create_vm_s_forgejo.main import create_vm_s_forgejo_bp
from api_gateway.main import api_gateway_bp

app = func.FunctionApp()

app.register_functions(hook_vm_bp)
app.register_functions(api_gateway_bp)
app.register_functions(create_vm_s_forgejo_bp)