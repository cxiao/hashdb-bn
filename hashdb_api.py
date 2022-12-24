import requests
from binaryninja import Settings


class HashDBError(Exception):
    pass


def get_algorithms(api_url=Settings().get_string("hashdb.url")):
    algorithms_url = api_url + "/hash"
    r = requests.get(algorithms_url)
    if not r.ok:
        raise HashDBError(
            f"Get hash API request failed, status {r.status_code} for URL: {hash_url}"
        )
    results = r.json()
    algorithms = [a.get("algorithm") for a in results.get("algorithms", [])]
    return algorithms


def get_strings_from_hash(
    algorithm, hash_value, api_url=Settings().get_string("hashdb.url")
):
    hash_url = api_url + "/hash/%s/%d" % (algorithm, hash_value)
    r = requests.get(hash_url)
    if not r.ok:
        raise HashDBError(
            f"Get hash API request failed, status {r.status_code} for URL: {hash_url}"
        )
    results = r.json()
    return results


def get_module_hashes(
    module_name, algorithm, permutation, api_url=Settings().get_string("hashdb.url")
):
    module_url = api_url + "/module/%s/%s/%s" % (module_name, algorithm, permutation)
    r = requests.get(module_url)
    if not r.ok:
        raise HashDBError(
            f"Get hash API request failed, status {r.status_code} for URL: {hash_url}"
        )
    results = r.json()
    return results


def hunt_hash(hash_value, api_url=Settings().get_string("hashdb.url")):
    matches = []
    hash_list = [hash_value]
    module_url = api_url + "/hunt"
    r = requests.post(module_url, json={"hashes": hash_list})
    if not r.ok:
        log_info(module_url)
        log_info(hash_list)
        log_info(r.json())
        raise HashDBError(
            f"Get hash API request failed, status {r.status_code} for URL: {hash_url}"
        )
    for hit in r.json().get("hits", []):
        algo = hit.get("algorithm", None)
        if (algo != None) and (algo not in matches):
            matches.append(algo)
    return matches
