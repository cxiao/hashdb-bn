########################################################################################
##
## This plugin is the client for the HashDB lookup service operated by OALABS:
##
## https://hashdb.openanalysis.net/
##
##   _   _           _    ____________ 
##  | | | |         | |   |  _  \ ___ \ 
##  | |_| | __ _ ___| |__ | | | | |_/ /
##  |  _  |/ _` / __| '_ \| | | | ___ \ 
##  | | | | (_| \__ \ | | | |/ /| |_/ /
##  \_| |_/\__,_|___/_| |_|___/ \____/ 
##
## HashDB is a community-sourced library of hashing algorithms used in malware.
## New hash algorithms can be added here: https://github.com/OALabs/hashdb
##
## Rewritten for Binary Ninnja by @psifertex, original IDA plugin by @herrcore
##
## To install:
##      - Install via the plugin manager! Or...
##      - Clone this repository (or download the bundle) into your plugin folder 
##        (Tools/Open Plugin Folder)
##
## To run:
##      Lookup Hash:
##          Highlight constant in Disassembly or any IL view
##          Right-click -> HashDB Lookup
##          If a hash is found it will be added to an enum controlled in the settings
##          Right-click on the constant again -> Enum -> Select new hash enum
##
## Credits: This Binary Ninja plugin was ported from the OALabs HashDB-IDA plugin
##          https://github.com/OALabs/hashdb-ida and is released under the same BSD 
##          3-Clause license.
##
## Todo: 
##          Create background threads for blocking tasks
##          Actually create enums, or investigate alternatives (vs just logging for now)
##          Test IAT creation method
##          Use new Workflows API to re-write function calls to the import
##
########################################################################################

import sys
from binaryninja import core_version, BinaryReader, Settings, interaction, enums
from binaryninjaui import (UIAction, UIActionHandler, Menu, DockHandler, UIContext)
from binaryninja.log import (log_error, log_info, log_warn)
import requests
import json


#--------------------------------------------------------------------------
# Global settings
#--------------------------------------------------------------------------

Settings().register_group("hashdb", "Open Analysis HashDB")
Settings().register_setting("hashdb.url", """
    {
        "title" : "HashDB API URL",
        "type" : "string",
        "default" : "https://hashdb.openanalysis.net",
        "description" : "URL of the server used to query HashDB",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)
Settings().register_setting("hashdb.enum_name", """
    {
        "title" : "Enum used for hashdb strings",
        "type" : "string",
        "default" : "hashdb_strings",
        "description" : "Enum populated with hashdb results",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)

# Using a global setting for the URL and enum_name so it can be changed
# system-wide and replacing the global variable with the settings API so
# they can be changed on the fly without having to reload the plugin ur 
# use a distinct settings system.
# 
# The xor and alg setting will be serialized into each analysis
# database's metadata.
ENUM_NAME = Settings().get_string("hashdb.enum_name") 
HASHDB_XOR_VALUE = 0
HASHDB_ALGORITHM = None
HASHDB_HASH_SIZE = 4

#--------------------------------------------------------------------------
# Error class
#--------------------------------------------------------------------------
class HashDBError(Exception):
    pass

#--------------------------------------------------------------------------
# HashDB API 
#--------------------------------------------------------------------------

def get_algorithms(api_url=Settings().get_string("hashdb.url")):
    algorithms_url = api_url + '/hash'
    r = requests.get(algorithms_url)
    if not r.ok:
        raise HashDBError(f"Get hash API request failed, status {r.status_code} for URL: {hash_url}")
    results = r.json()
    algorithms = [a.get('algorithm') for a in results.get('algorithms',[])]
    return algorithms


def get_strings_from_hash(algorithm, hash_value, xor_value=0, api_url=Settings().get_string("hashdb.url")):
    hash_value ^= xor_value
    hash_url = api_url + '/hash/%s/%d' % (algorithm, hash_value)
    r = requests.get(hash_url)
    if not r.ok:
        raise HashDBError(f"Get hash API request failed, status {r.status_code} for URL: {hash_url}")
    results = r.json()
    return results


def get_module_hashes(module_name, algorithm, permutation, api_url=Settings().get_string("hashdb.url")):
    module_url = api_url + '/module/%s/%s/%s' % (module_name, algorithm, permutation)
    r = requests.get(module_url)
    if not r.ok:
        raise HashDBError(f"Get hash API request failed, status {r.status_code} for URL: {hash_url}")
    results = r.json()
    return results


def hunt_hash(hash_value, api_url=Settings().get_string("hashdb.url")):
    matches = []
    hash_list = [hash_value]
    module_url = api_url + '/hunt'
    r = requests.post(module_url, json={"hashes": hash_list})
    if not r.ok:
        log_info(module_url)
        log_info(hash_list)
        log_info(r.json())
        raise HashDBError(f"Get hash API request failed, status {r.status_code} for URL: {hash_url}")
    for hit in r.json().get('hits',[]):
        algo = hit.get('algorithm',None)
        if (algo != None) and (algo not in matches):
            matches.append(algo)
    return matches

#--------------------------------------------------------------------------
# Set xor key
#--------------------------------------------------------------------------
def set_xor_key(context):
    """
    Set xor key from selection
    """
    bv = context.binaryView
    token = context.token.token
    if token and token.type == enums.InstructionTextTokenType.IntegerToken:
        if token.text.startswith('-'):
            #Handle negatives later
            log_warn("HashDB: plugin does not currently handle negative values.")
            return
        xor_value = token.value
        bv.store_metadata("HASHDB_XOR_VALUE", xor_value) 
        log_info(f"HashDB: XOR key set: {hex(xor_value)}")
        return True
    else:
        log_info(f"HashDB: failed to set XOR key.")
        return False
    

#--------------------------------------------------------------------------
# Hash lookup
#--------------------------------------------------------------------------
def hash_lookup(context):
    """
    Lookup hash from highlighted text
    """
    bv = context.binaryView
    token = context.token.token
    HASHDB_XOR_VALUE = 0
    HASHDB_ALGORITHM = get_hash(bv)
    try:
        HASHDB_XOR_VALUE = bv.query_metadata("HASHDB_XOR_VALUE")
    except:
        pass

    if HASHDB_ALGORITHM is None:
        log_error('HashDB: No hash selected.')
        return

    if token and token.type == enums.InstructionTextTokenType.IntegerToken:
        if token.text.startswith('-'):
            #Handle negatives later
            log_warn("HashDB: plugin does not currently handle negative values.")
            return
        hash_value = token.value
        hash_value ^= HASHDB_XOR_VALUE

        # Lookup hash
        try:
            hash_results = get_strings_from_hash(HASHDB_ALGORITHM, hash_value, xor_value=HASHDB_XOR_VALUE)
        except Exception as e:
            log_error(f"HashDB: API request failed: {e}")
            return
        hash_list = hash_results.get('hashes',[])
        if len(hash_list) == 0:
            log_warn(f"HashDB: No Hash found for {hex(hash_value)}")
            return
        elif len(hash_list) == 1:
            hash_string = hash_list[0].get('string',{})
        else:
            # Multiple hashes found
            # Allow the user to select the best match
            collisions = {}
            for string_match in hash_list:
                string_value = string_match.get('string','')
                if string_value.get('is_api',False):
                    collisions[string_value.get('api','')] = string_value
                else:
                    collisions[string_value.get('string','')] = string_value
            string_selection = interaction.get_choice_input("Select the best match: ", "String Selection", list(collisions.keys()))
            if string_selection is not None:
                selected_string = list(collisions.keys())[string_selection]
            else:
                # User cancelled, select the first one?
                selected_string = list(collisions.keys())[0]
            hash_string = collisions[selected_string]

        # Parse string from hash_string match
        if hash_string.get('is_api',False):
            string_value = hash_string.get('api','')
        else:
            string_value = hash_string.get('string','')

        log_info(f"Hash match found: {string_value}")
        # TODO: Add hash to enum
        if hash_string.get('is_api',False):
            # If the hash is an API ask if the user wants to 
            # import all of the hashes from the module and permutation
            modules = hash_string.get('modules',[])
            modules.sort()
            module_choice = interaction.get_choice_input(f"The hash for {string_value} is a module function.\n\nDo you want to import all function hashes from this module?","HashDB Bulk Import", modules)
            if module_choice is not None:
                module_name = modules[module_choice]
                if module_name != None:
                    try:
                        #TODO: Background thread 
                        module_hash_list = get_module_hashes(module_name, HASHDB_ALGORITHM, hash_string.get('permutation',''))
                        # Parse hash and string from list into tuple list [(string,hash)]
                        enum_list = []
                        for function_entry in module_hash_list.get('hashes',[]):
                            # If xor is enabled we must convert the hashes
                            enum_list.append((function_entry.get('string',{}).get('api',''),HASHDB_XOR_VALUE^function_entry.get('hash',0)))
                        # Add hashes to enum
                        #TODO: Add hashes for the module
                        log_info(enum_list)
                        #enum_id = add_enums(ENUM_NAME, enum_list)
                        #if enum_id == None:
                            #idaapi.msg("ERROR: Unable to create or find enum: %s\n" % ENUM_NAME)
                        #else:
                            #idaapi.msg("Added %d hashes for module %s\n" % (len(enum_list),module_name))
                    except Exception as e:
                        log_error(f"HashDB: ERROR {e}")
                        return
                else:
                    log_error("HashDB: Invalid module name specified.")
    else:
        log_error("HashDB: Invalid hash selected.")
        return
    return 


def change_hash(context):
    context.binaryView.remove_metadata("HASHDB_ALGORITHM")
    get_hash(context.binaryView)


#--------------------------------------------------------------------------
# Ask for a hash
#--------------------------------------------------------------------------
def get_hash(bv):
    HASHDB_ALGORITHM = None
    try:
        HASHDB_ALGORITHM = bv.query_metadata("HASHDB_ALGORITHM")
    except:
        pass
    
    if HASHDB_ALGORITHM is None:
        algorithms = get_algorithms()
        algorithms.sort()
        algorithm_choice = interaction.get_choice_input("Select an algorithm:", "Algorithms", algorithms)
        if algorithm_choice is not None:
            result = algorithms[algorithm_choice]
            bv.store_metadata("HASHDB_ALGORITHM", result)
            return result
        else:
            return None
    else:
        return HASHDB_ALGORITHM

#--------------------------------------------------------------------------
# Dynamic IAT hash scan
#--------------------------------------------------------------------------
def hash_scan(context):
    """
    Lookup hash from highlighted text
    """
    bv = context.binaryView
    HASHDB_XOR_VALUE = 0
    HASHDB_ALGORITHM = get_hash(bv)
    log_info(f"outside: {HASHDB_ALGORITHM}")
    try:
        HASHDB_XOR_VALUE = bv.query_metadata("HASHDB_XOR_VALUE")
    except:
        pass

    # If there is no algorithm give the user a chance to choose one
    if HASHDB_ALGORITHM == None:
        log_error("HashDB: You must select a hash to continue.")
        return
    try:
        br = BinaryReader(bv, bv.endianness)
        br.seek(context.address)
        while br.offset < (context.address + context.length):
            hash_value = br.read32()
            hash_results = get_strings_from_hash(HASHDB_ALGORITHM, hash_value, xor_value=HASHDB_XOR_VALUE)

            # Extract hash info from results
            hash_list = hash_results.get('hashes',[])
            if len(hash_list) == 0:
                # No hash found 
                # Increment the counter and continue 
                continue 
            elif len(hash_list) == 1:
                hash_string = hash_list[0].get('string',{})
            else:
                collisions = {}
                for string_match in hash_list:
                    string_value = string.match.get('string', '')
                    if string_value.get('is_api', False):
                        collisions[string_value.get('api','')] = string_value
                    else:
                        collisions[string_value.get('string','')] = string_value
                hash_choice = interaction.get_choice_input("Select the best hash: ", "Hash Selection", collisions.keys())
                if hash_choice is not None:
                    hash_string = collisions.keys()[hash_choice]
                else:
                    # User cancelled, select the first one?
                    hash_string = collisions.keys()[0]

            # Parse string from hash_string match
            if hash_string.get('is_api',False):
                string_value = hash_string.get('api','')
            else:
                string_value = hash_string.get('string','')
            log_info(f"HashDB: Hash match found: {string_value}")
            # Add hash to enum
            # TODO
    except Exception as e:
        log_error(f"HashDB: ERROR: {e}")
        return
    return


#--------------------------------------------------------------------------
# Algorithm search function
#--------------------------------------------------------------------------
def hunt_algorithm(context):
    bv = context.binaryView
    HASHDB_XOR_VALUE = 0
    try:
        HASHDB_XOR_VALUE = bv.query_metadata("HASHDB_XOR_VALUE")
    except:
        pass

    # Get selected hash
    token = context.token.token
    if token and token.type == enums.InstructionTextTokenType.IntegerToken:
        if token.text.startswith('-'):
            #Handle negatives later
            log_warn("HashDB: plugin does not currently handle negative values.")
            return
        hash_value = token.value
        hash_value ^= HASHDB_XOR_VALUE
        try:
            #TODO: Convert to a background task for status indicator 
            match_results = hunt_hash(hash_value, api_url=Settings().get_string("hashdb.url"))
            match_results.sort()
        except Exception as e:
            log_error(f"HashDB HashDB API request failed: {e}")
            return
        if len(match_results) == 0:
            interaction.show_message_box("No Match", "No algorithms matched the hash.")
        else:
            msg = "The following algorithms contain a matching hash.\nSelect an algorithm to set as the default for this binary."
            choice = interaction.get_choice_input(msg, "Select a hash", match_results)
            bv.store_metadata("HASHDB_ALGORITHM", match_results[choice])
    else:
        log_warn("HashDB: This token does not look like a valid integer.")


#--------------------------------------------------------------------------
# Plugin Registration
#--------------------------------------------------------------------------
def plugin_parent_menu() -> str:
    parent_menu = "Tools"
    version = core_version()
    if version and int(version[4:][:4]) >= 3505:
        parent_menu = "Plugins"
    return parent_menu

for (action, target, add_to_menu) in [["HashDB\\Hash Lookup", hash_lookup, False],
                         ["HashDB\\Set Xor...", set_xor_key, False], 
                         ["HashDB\\Hunt", hunt_algorithm, False], 
                         ["HashDB\\IAT Scan", hash_scan, True],
                         ["HashDB\\Reset Hash", change_hash, True]]:
    UIAction.registerAction(action)
    UIActionHandler.globalActions().bindAction(action, UIAction(target))
    if add_to_menu:
        Menu.mainMenu(plugin_parent_menu()).addAction(action, "HashDB")