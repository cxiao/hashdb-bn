"""
Module for interacting with the HashDB API.

This module performs requests against the API, and provides types representing hash lookup results deserialized from the data returned by the API.

The module can interact with the original service at hashdb.openanalysis.net, or can interact with any other HashDB service instance which conforms to the OpenAPI specification at https://hashdb.openanalysis.net/openapi.json.
"""

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin
import binaryninja
import httpx

logger = binaryninja.log.Logger(session_id=0, logger_name=__name__)


class HashDBError(Exception):
    pass


@dataclass
class AlgorithmType:
    """
    Represents the data type and data size, in bytes, of the values produced by a specific hash algorithm.
    """

    name: str
    size: int

    @classmethod
    def from_raw_name(cls, raw_name: str):
        if raw_name == "unsigned_int":
            return cls(
                name="unsigned_int",
                size=4,
            )
        elif raw_name == "unsigned_long":
            return cls(
                name="unsigned_long",
                size=8,
            )
        else:
            raise KeyError("Could not parse unknown algorithm type {raw_name}")

    def __str__(self) -> str:
        return f"{self.name} ({self.size} bytes)"


@dataclass
class Algorithm:
    """
    Represents the type `components/schemas/algorithm` in the HashDB OpenAPI specification.
    For example, `GET /hash/{algorithm}` returns an instance of this type of object.
    """

    algorithm: str
    description: str
    type: AlgorithmType

    @classmethod
    def from_dict(cls, src: Dict[str, Any]):
        result = cls(
            algorithm=src["algorithm"],
            description=src["description"],
            type=AlgorithmType.from_raw_name(src["type"]),
        )
        return result

    def __str__(self) -> str:
        return f"{self.algorithm} ({self.type}): {self.description}"


@dataclass
class HashString:
    """
    Represents the type `components/schemas/string` in the HashDB OpenAPI specification.
    For example, `GET /string/{string}` returns an instance of this type of object.
    """

    string: str
    is_api: bool
    permutation: Optional[str]
    api: Optional[str]
    modules: Optional[List[str]]

    @classmethod
    def from_dict(cls, src: Dict[str, Any]):
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
    """
    Represents the type `components/schemas/hash` in the HashDB OpenAPI specification.
    For example, `GET /hash/{algorithm}/{hash}` returns an array containing this type of object.
    """

    value: int
    hash_string: HashString

    @classmethod
    def from_dict(cls, src: Dict[str, Any]):
        result = cls(
            value=src["hash"],
            hash_string=HashString.from_dict(src["string"]),
        )
        return result


@dataclass
class HuntMatch:
    """
    Represents the type `components/schemas/hit` in the HashDB OpenAPI specification.
    For example, `POST /hunt` returns an array containing this type of object.
    """

    algorithm: str
    count: int
    hitrate: int

    @classmethod
    def from_dict(cls, src: Dict[str, Any]):
        result = cls(
            algorithm=src["algorithm"],
            count=src["count"],
            hitrate=src["hitrate"],
        )
        return result


TIMEOUT = httpx.Timeout(15, connect=3)


def get_algorithms(api_url: str) -> List[Algorithm]:
    """
    Get a list of all hash algorithms known to this HashDB instance.
    Results are sorted by algorithm name.
    """
    request_url = urljoin(api_url, "/hash")
    logger.log_debug(f"get_algorithms requested URL: {request_url}")

    try:
        r = httpx.get(request_url, timeout=TIMEOUT)
    except httpx.RequestError as connection_err:
        raise HashDBError(
            f"Get algorithm API request failed for URL {request_url} with a network error: {connection_err}"
        )

    if not r.is_success:
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
    """
    Given an algorithm and a hash value, get the corresponding string which produced the hash.
    """
    request_url = urljoin(api_url, f"/hash/{algorithm:s}/{hash_value:d}")
    logger.log_debug(f"get_strings_from_hash requested URL: {request_url}")

    try:
        r = httpx.get(request_url, timeout=TIMEOUT)
    except httpx.RequestError as connection_err:
        raise HashDBError(
            f"Get hash API request failed for URL {request_url} with a network error: {connection_err}"
        )
    if not r.is_success:
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


async def _get_strings_from_hashes_inner(
    algorithm: str, hash_values: List[int], api_url: str
) -> List[Union[List[Hash], HashDBError]]:
    async def request_task(client, request_url) -> List[Hash]:
        logger.log_debug(f"get_strings_from_hashes requested URL: {request_url}")
        try:
            r = await client.get(request_url, timeout=TIMEOUT)
        except httpx.RequestError as connection_err:
            raise HashDBError(
                f"Get hash API request failed for URL {request_url} with a network error: {connection_err}"
            )
        if not r.is_success:
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

    request_urls = [
        urljoin(api_url, f"/hash/{algorithm:s}/{hash_value:d}")
        for hash_value in hash_values
    ]
    request_tasks = []

    async with httpx.AsyncClient() as client:
        for request_url in request_urls:
            request_tasks.append(
                asyncio.ensure_future(request_task(client, request_url))
            )

        hash_results = await asyncio.gather(*request_tasks, return_exceptions=True)
        return hash_results


def get_strings_from_hashes(
    algorithm: str, hash_values: List[int], api_url: str
) -> List[Union[List[Hash], HashDBError]]:
    """
    Given an algorithm and a list of hash values, get the corresponding strings which produced the hashes.
    """
    return asyncio.run(_get_strings_from_hashes_inner(algorithm, hash_values, api_url))


def get_module_hashes(
    module_name: str, algorithm: str, permutation: str, api_url: str
) -> List[Hash]:
    """
    Given the name of a module (such as a Win32 API library), return a list of the hashes of the names of all APIs which are part of the module.
    """
    request_url = urljoin(
        api_url, f"/module/{module_name:s}/{algorithm:s}/{permutation:s}"
    )
    logger.log_debug(f"get_module_hashes requested URL: {request_url}")

    try:
        r = httpx.get(request_url, timeout=TIMEOUT)
    except httpx.RequestError as connection_err:
        raise HashDBError(
            f"Get hash API request failed for URL {request_url} with a network error: {connection_err}"
        )
    if not r.is_success:
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
    """
    Given a hash value, get a list of possible hash algorithms which could have produced the hash value.
    """
    matches = []
    hash_list = [hash_value]
    request_url = urljoin(api_url, "/hunt")
    request_data = {"hashes": hash_list}
    logger.log_debug(
        f"hunt_hash requested URL: {request_url} with request data\n{request_data}"
    )

    try:
        r = httpx.post(
            request_url,
            json=request_data,
            timeout=TIMEOUT,
        )
    except httpx.RequestError as connection_err:
        raise HashDBError(
            f"Hunt hash API request failed for URL {request_url} with a network error: {connection_err}"
        )

    if not r.is_success:
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
