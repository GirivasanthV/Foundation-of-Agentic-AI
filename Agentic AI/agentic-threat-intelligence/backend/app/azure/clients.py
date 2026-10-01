from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.storage.blob import BlobServiceClient
from openai import AzureOpenAI, OpenAI

from app.config import Settings


def azure_openai_client(settings: Settings) -> AzureOpenAI:
    if not settings.azure_openai_endpoint or not settings.azure_openai_api_key:
        raise RuntimeError("Azure model credentials are not configured")
    return AzureOpenAI(
        azure_endpoint=settings.azure_openai_endpoint,
        api_key=settings.azure_openai_api_key,
        api_version=settings.azure_openai_api_version,
    )


def vlm_client(settings: Settings) -> OpenAI:
    return OpenAI(base_url=settings.vlm_base_url, api_key=settings.vlm_api_key)


def azure_search_client(settings: Settings) -> SearchClient:
    if not settings.azure_search_endpoint or not settings.azure_search_api_key:
        raise RuntimeError("Azure AI Search credentials are not configured")
    return SearchClient(
        endpoint=settings.azure_search_endpoint,
        index_name=settings.azure_search_index,
        credential=AzureKeyCredential(settings.azure_search_api_key),
    )


def azure_blob_client(settings: Settings) -> BlobServiceClient:
    if not settings.azure_storage_connection_string:
        raise RuntimeError("Azure Blob Storage is not configured")
    return BlobServiceClient.from_connection_string(settings.azure_storage_connection_string)

