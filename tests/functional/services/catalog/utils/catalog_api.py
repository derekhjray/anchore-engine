import os
from typing import Dict

from tests.functional.services.utils import http_utils

CATALOG_API_CONF = http_utils.DEFAULT_API_CONF.copy()
CATALOG_API_CONF["ANCHORE_BASE_URL"] = os.environ.get(
    "ANCHORE_CATALOG_URL", "http://localhost:8230/v1"
)


def catalog_api_conf():
    return CATALOG_API_CONF


def add_document(bucket: str, archiveid: str, object: Dict) -> http_utils.APIResponse:
    if not bucket:
        raise ValueError("Cannot add document to object store without bucket")

    if not archiveid:
        raise ValueError("Cannot add document to object store without archiveid")

    if not object:
        raise ValueError("Cannot add document to object store without object")

    payload = object

    add_document_resp = http_utils.http_post(
        ["objects", bucket, archiveid], payload, config=catalog_api_conf
    )

    if add_document_resp.code != 200:
        raise http_utils.RequestFailedError(
            add_document_resp.url, add_document_resp.code, add_document_resp.body
        )

    return add_document_resp


def delete_document(bucket: str, archiveid: str) -> http_utils.APIResponse:
    if not bucket:
        raise ValueError("Cannot delete document to object store without bucket")

    if not archiveid:
        raise ValueError("Cannot delete document to object store without archiveid")

    del_document_resp = http_utils.http_del(
        ["objects", bucket, archiveid], config=catalog_api_conf
    )

    if del_document_resp.code != 200:
        raise http_utils.RequestFailedError(
            del_document_resp.url, del_document_resp.code, del_document_resp.body
        )

    return del_document_resp