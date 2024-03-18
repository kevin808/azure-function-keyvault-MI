import os
import azure.functions as func
import datetime
import json
import logging
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.certificates import CertificateClient

app = func.FunctionApp()

@app.route(route="http_trigger", auth_level=func.AuthLevel.FUNCTION)
def http_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    # Check for MSI_SECRET environment variable
    if 'MSI_SECRET' not in os.environ:
        return func.HttpResponse(
            "Managed Identity was not enabled.",
            status_code=400
        )

    KEY_VAULT_URL = "https://your-vault.vault.azure.net/"

    try:
        credential = DefaultAzureCredential()

        # Get secret from Azure Key Vault
        secret_name = "test"
        secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
        retrieved_secret = secret_client.get_secret(secret_name)
        print(f"The secret value is: {retrieved_secret.value}")

        # Similarily, get certificate from Azure Key Vault
        # certificate_client = CertificateClient(vault_url=KEY_VAULT_URL, credential=credential)
        # certificate_name = "test"
        # certificate = certificate_client.get_certificate(certificate_name)
        # print("Certificate Name:", certificate.name)
        # print("Certificate Value:", certificate.cer)

        # Return retrieved secret if available
        if retrieved_secret and retrieved_secret.value:
            return func.HttpResponse(f"Hello, The secret value is: {retrieved_secret.value}.")
        else:
            return func.HttpResponse(
                 "No value found",
                 status_code=200
            )
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return func.HttpResponse(
            f"An error occurred: {str(e)}",
            status_code=500
        )
