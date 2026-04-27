import time
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth


class QualysClient:
    RETRY_STATUS_CODES = {429, 503}
    MAX_RETRIES = 5

    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.auth = HTTPBasicAuth(username, password)
        self._session.headers.update({"X-Requested-With": "SekoiaConnector"})

    def _request(self, method: str, endpoint_or_url: str, **kwargs: object) -> str:
        if endpoint_or_url.startswith("http"):
            url = endpoint_or_url
        else:
            url = f"{self.base_url}{endpoint_or_url}"

        retries = 0
        while True:
            response = self._session.request(method, url, **kwargs)
            if response.status_code in self.RETRY_STATUS_CODES and retries < self.MAX_RETRIES:
                time.sleep(2**retries)
                retries += 1
                continue
            response.raise_for_status()
            return response.text

    def get(self, endpoint_or_url: str, params: Optional[dict] = None) -> str:
        return self._request("GET", endpoint_or_url, params=params or {})

    def post(self, endpoint_or_url: str, data: Optional[dict] = None) -> str:
        return self._request("POST", endpoint_or_url, data=data or {})
