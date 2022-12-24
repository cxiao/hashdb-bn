from typing import List
import requests


class HashDBError(Exception):
    pass


def get_algorithms(api_url: str) -> List[str]:
    request_url = api_url + "/hash"
    r = requests.get(request_url)
    if not r.ok:
        raise HashDBError(
            f"Get hash API request failed, status {r.status_code} for URL: {request_url}"
        )
    results = r.json()
    algorithms = [a.get("algorithm") for a in results.get("algorithms", [])]
    return algorithms


def get_strings_from_hash(algorithm: str, hash_value: int, api_url: str):
    request_url = api_url + "/hash/%s/%d" % (algorithm, hash_value)
    r = requests.get(request_url)
    if not r.ok:
        raise HashDBError(
            f"Get hash API request failed, status {r.status_code} for URL: {request_url}"
        )
    results = r.json()
    return results


def get_module_hashes(module_name: str, algorithm: str, permutation: str, api_url: str):
    request_url = api_url + "/module/%s/%s/%s" % (module_name, algorithm, permutation)
    r = requests.get(request_url)
    if not r.ok:
        raise HashDBError(
            f"Get hash API request failed, status {r.status_code} for URL: {request_url}"
        )
    results = r.json()
    return results


def hunt_hash(hash_value: int, api_url: str) -> List:
    matches = []
    hash_list = [hash_value]
    request_url = api_url + "/hunt"
    r = requests.post(request_url, json={"hashes": hash_list})
    if not r.ok:
        log_info(request_url)
        log_info(hash_list)
        log_info(r.json())
        raise HashDBError(
            f"Get hash API request failed, status {r.status_code} for URL: {request_url}"
        )
    for hit in r.json().get("hits", []):
        algo = hit.get("algorithm", None)
        if (algo != None) and (algo not in matches):
            matches.append(algo)
    return matches
