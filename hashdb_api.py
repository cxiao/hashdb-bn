from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Self, Type
from urllib.parse import urljoin
import binaryninja
import requests

logger = binaryninja.log.Logger(session_id=0, logger_name=__name__)


class HashDBError(Exception):
    pass


@dataclass
class Algorithm:
    algorithm: str
    description: str
    type: str

    @classmethod
    def from_dict(cls: Type[Self], src: Dict[str, Any]) -> Self:
        result = cls(
            algorithm=src["algorithm"],
            description=src["description"],
            type=src["type"],
        )
        return result

    def __str__(self) -> str:
        return f"{self.algorithm} ({self.type}): {self.description}"


@dataclass
class HashString:
    string: str
    is_api: bool
    permutation: Optional[str]
    api: Optional[str]
    modules: Optional[List[str]]

    @classmethod
    def from_dict(cls: Type[Self], src: Dict[str, Any]) -> Self:
        result = cls(
            string=src["string"],
            is_api=src["is_api"],
            permutation=src.get("permutation"),
            api=src.get("api"),
            modules=src.get("modules"),
        )
        return result

    def get_api_string_if_available(self) -> str:
        if self.is_api and self.api is not None:
            return self.api
        else:
            return self.string


@dataclass
class Hash:
    value: int
    hash_string: HashString

    @classmethod
    def from_dict(cls: Type[Self], src: Dict[str, Any]) -> Self:
        result = cls(
            value=src["hash"],
            hash_string=HashString.from_dict(src["string"]),
        )
        return result


@dataclass
class HuntMatch:
    algorithm: str
    count: int
    hitrate: int

    @classmethod
    def from_dict(cls: Type[Self], src: Dict[str, Any]) -> Self:
        result = cls(
            algorithm=src["algorithm"],
            count=src["count"],
            hitrate=src["hitrate"],
        )
        return result


CONNECTION_ESTABLISH_TIMEOUT = 3
SERVER_RESPONSE_TIMEOUT = 15


def get_algorithms(api_url: str) -> List[Algorithm]:
    request_url = urljoin(api_url, "/hash")
    logger.log_debug(f"get_algorithms requested URL: {request_url}")

    try:
        r = requests.get(
            request_url, timeout=(CONNECTION_ESTABLISH_TIMEOUT, SERVER_RESPONSE_TIMEOUT)
        )
    except (requests.ConnectionError, requests.Timeout) as connection_err:
        raise HashDBError(
            f"Get algorithm API request failed for URL {request_url} with a network error: {connection_err}"
        )

    if not r.ok:
        raise HashDBError(
            f"Get algorithm API request failed for URL {request_url} with status code {r.status_code}"
        )

    results = r.json()
    logger.log_debug(
        f"get_algorithms request to URL: {request_url} returned results\n{results}"
    )
    try:
        algorithms = [
            Algorithm.from_dict(algorithm) for algorithm in results["algorithms"]
        ]
    except KeyError as parsing_key_error:
        raise HashDBError(
            f"Could not parse the following response from URL {request_url} as a valid list of algorithms; parsing failed to find required key {parsing_key_error}:\n{results}"
        )
    return sorted(algorithms, key=lambda algorithm: algorithm.algorithm)


def get_strings_from_hash(algorithm: str, hash_value: int, api_url: str) -> List[Hash]:
    request_url = urljoin(api_url, f"/hash/{algorithm:s}/{hash_value:d}")
    logger.log_debug(f"get_strings_from_hash requested URL: {request_url}")

    try:
        r = requests.get(
            request_url, timeout=(CONNECTION_ESTABLISH_TIMEOUT, SERVER_RESPONSE_TIMEOUT)
        )
    except (requests.ConnectionError, requests.Timeout) as connection_err:
        raise HashDBError(
            f"Get hash API request failed for URL {request_url} with a network error: {connection_err}"
        )
    if not r.ok:
        raise HashDBError(
            f"Get hash API request failed for URL {request_url} with status code {r.status_code}"
        )

    results = r.json()
    logger.log_debug(
        f"get_strings_from_hash request to URL: {request_url} returned results\n{results}"
    )
    try:
        hashes = [Hash.from_dict(hash_) for hash_ in results["hashes"]]
    except KeyError as parsing_key_error:
        raise HashDBError(
            f"Could not parse the following response from URL {request_url} as a valid list of hashes; parsing failed to find required key {parsing_key_error}:\n{results}"
        )
    return hashes


def get_module_hashes(
    module_name: str, algorithm: str, permutation: str, api_url: str
) -> List[Hash]:
    request_url = urljoin(
        api_url, f"/module/{module_name:s}/{algorithm:s}/{permutation:s}"
    )
    logger.log_debug(f"get_module_hashes requested URL: {request_url}")

    try:
        r = requests.get(
            request_url, timeout=(CONNECTION_ESTABLISH_TIMEOUT, SERVER_RESPONSE_TIMEOUT)
        )
    except (requests.ConnectionError, requests.Timeout) as connection_err:
        raise HashDBError(
            f"Get hash API request failed for URL {request_url} with a network error: {connection_err}"
        )
    if not r.ok:
        raise HashDBError(
            f"Get hash API request failed for URL {request_url} with status code {r.status_code}"
        )

    results = r.json()
    logger.log_debug(
        f"get_module_hashes request to URL: {request_url} returned results\n{results}"
    )
    try:
        hashes = [Hash.from_dict(hash_) for hash_ in results["hashes"]]
    except KeyError as parsing_key_error:
        raise HashDBError(
            f"Could not parse the following response from URL {request_url} as a valid list of hashes; parsing failed to find required key {parsing_key_error}:\n{results}"
        )
    return hashes


def hunt_hash(hash_value: int, api_url: str) -> List[HuntMatch]:
    matches = []
    hash_list = [hash_value]
    request_url = urljoin(api_url, "/hunt")
    request_data = {"hashes": hash_list}
    logger.log_debug(
        f"hunt_hash requested URL: {request_url} with request data\n{request_data}"
    )

    try:
        r = requests.post(
            request_url,
            json=request_data,
            timeout=(CONNECTION_ESTABLISH_TIMEOUT, SERVER_RESPONSE_TIMEOUT),
        )
    except (requests.ConnectionError, requests.Timeout) as connection_err:
        raise HashDBError(
            f"Hunt hash API request failed for URL {request_url} with a network error: {connection_err}"
        )

    if not r.ok:
        raise HashDBError(
            f"Hunt hash API request failed for URL {request_url} with status code {r.status_code}, using the following sent request data:\n{request_data}"
        )

    results = r.json()
    logger.log_debug(
        f"hunt_hash request to URL: {request_url} returned results\n{results}"
    )
    try:
        matches = [HuntMatch.from_dict(hit) for hit in results["hits"]]
    except KeyError as parsing_key_error:
        raise HashDBError(
            f"Could not parse the following response from URL {request_url} as a valid list of hunt matches; parsing failed to find required key {parsing_key_error}:\n{results}"
        )
    return sorted(matches, key=lambda match: match.count)
