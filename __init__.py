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
## Rewritten for Binary Ninja by @psifertex, original IDA plugin by @herrcore
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

from typing import List, Optional, Tuple

from binaryninja import core_version, BinaryReader, BinaryView, Settings, interaction, enums
from binaryninjaui import (UIAction, UIActionHandler, Menu, DockHandler, UIContext)
from binaryninja.enums import TypeClass
from binaryninja.log import Logger
from binaryninja.types import EnumerationBuilder, Type
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.mainthread import execute_on_main_thread

from . import hashdb_api as api


#--------------------------------------------------------------------------
# Global settings
#--------------------------------------------------------------------------
logger = Logger(session_id=0, logger_name=__name__)

DEFAULT_ENUM_NAME = "hashdb_strings"

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
Settings().register_setting("hashdb.enum_name", f"""
    {{
        "title" : "Enum used for hashdb strings",
        "type" : "string",
        "default" : {DEFAULT_ENUM_NAME},
        "description" : "Enum populated with hashdb results",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }}
    """)

# Using a global setting for the URL and enum_name so it can be changed
# system-wide and replacing the global variable with the settings API so
# they can be changed on the fly without having to reload the plugin ur
# use a distinct settings system.
#
# The xor and alg setting will be serialized into each analysis
# database's metadata.
ENUM_NAME = Settings().get_string("hashdb.enum_name")
if ENUM_NAME is None:
    ENUM_NAME = DEFAULT_ENUM_NAME
HASHDB_XOR_VALUE = 0
HASHDB_ALGORITHM = None
HASHDB_HASH_SIZE = 4

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
            logger.log_warn("plugin does not currently handle negative values.")
            return
        xor_value = token.value
        bv.store_metadata("HASHDB_XOR_VALUE", xor_value)
        logger.log_info(f"XOR key set: {hex(xor_value)}")
        return True
    else:
        logger.log_info(f"failed to set XOR key.")
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
        logger.log_error('No hash selected.')
        return

    if token and token.type == enums.InstructionTextTokenType.IntegerToken:
        if token.text.startswith('-'):
            #Handle negatives later
            logger.log_warn("plugin does not currently handle negative values.")
            return
        hash_value = token.value
        hash_value ^= HASHDB_XOR_VALUE

        # Lookup hash
        try:
            hash_results = api.get_strings_from_hash(HASHDB_ALGORITHM, hash_value, api_url=Settings().get_string("hashdb.url"))
        except Exception as e:
            logger.log_error(f"API request failed: {e}")
            return
        hash_list = hash_results.get('hashes',[])
        if len(hash_list) == 0:
            logger.log_warn(f"No Hash found for {hex(hash_value)}")
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

        logger.log_info(f"Hash match found: {string_value}")
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
                        module_hash_list = api.get_module_hashes(module_name, HASHDB_ALGORITHM, hash_string.get('permutation',''), api_url=Settings().get_string("hashdb.url"))
                        # Parse hash and string from list into tuple list [(string,hash)]
                        hash_list = []
                        for function_entry in module_hash_list.get('hashes',[]):
                            # If xor is enabled we must convert the hashes
                            hash_list.append((function_entry.get('string',{}).get('api',''),HASHDB_XOR_VALUE^function_entry.get('hash',0)))
                        # Add hashes to enum
                        #TODO: Add hashes for the module
                        logger.log_info(hash_list)
                        add_enums(bv, ENUM_NAME, hash_list)
                        #enum_id = add_enums(ENUM_NAME, enum_list)
                        #if enum_id == None:
                            #idaapi.msg("ERROR: Unable to create or find enum: %s\n" % ENUM_NAME)
                        #else:
                            #idaapi.msg("Added %d hashes for module %s\n" % (len(enum_list),module_name))
                    except Exception as e:
                        logger.log_error(f"ERROR {e}")
                        return
                else:
                    logger.log_error("Invalid module name specified.")
    else:
        logger.log_error("Invalid hash selected.")
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
        algorithms = api.get_algorithms(api_url=Settings().get_string("hashdb.url"))
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
    logger.log_info(f"outside: {HASHDB_ALGORITHM}")
    try:
        HASHDB_XOR_VALUE = bv.query_metadata("HASHDB_XOR_VALUE")
    except:
        pass

    # If there is no algorithm give the user a chance to choose one
    if HASHDB_ALGORITHM == None:
        logger.log_error("You must select a hash to continue.")
        return
    try:
        br = BinaryReader(bv, bv.endianness)
        br.seek(context.address)
        while br.offset < (context.address + context.length):
            hash_value = br.read32()
            hash_value ^= HASHDB_XOR_VALUE
            hash_results = api.get_strings_from_hash(HASHDB_ALGORITHM, hash_value, api_url=Settings().get_string("hashdb.url"))

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
            logger.log_info(f"Hash match found: {string_value}")
            # Add hash to enum
            # TODO
    except Exception as e:
        logger.log_error(f"ERROR: {e}")
        return
    return


#--------------------------------------------------------------------------
# Algorithm search function
#--------------------------------------------------------------------------
class HuntAlgorithmTask(BackgroundTaskThread):
    def __init__(self, context, hash_value):
        super().__init__(initial_progress_text="[HashDB] Algorithm hunt task starting...", can_cancel=False)
        self.context = context
        self.match_results = None
        self.hash_value = hash_value

    def run(self):
        self.task_fn(self.hash_value)
        execute_on_main_thread(self.callback_fn)

    def task_fn(self, hash_value):
        try:
            match_results = api.hunt_hash(hash_value, api_url=Settings().get_string("hashdb.url"))
            match_results.sort()
            self.match_results = match_results
        except Exception as e:
            logger.log_error(f"HashDB API request failed: {e}")
            return

    def callback_fn(self):
        if self.match_results is None or len(self.match_results) == 0:
            interaction.show_message_box("No Match", "No algorithms matched the hash.")
        else:
            msg = """The following algorithms contain a matching hash.
            Select an algorithm to set as the default for this binary."""
            choice = interaction.get_choice_input(msg, "Select a hash", self.match_results)
            self.context.binaryView.store_metadata("HASHDB_ALGORITHM", self.match_results[choice])


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
            logger.log_warn("plugin does not currently handle negative values.")
            return
        hash_value = token.value
        hash_value ^= HASHDB_XOR_VALUE
        HuntAlgorithmTask(context=context, hash_value=hash_value).start()
    else:
        logger.log_warn("This token does not look like a valid integer.")


#--------------------------------------------------------------------------
# Enum creation
#--------------------------------------------------------------------------
def add_enums(bv: BinaryView, enum_name: str, hash_list: List[Tuple[str, int]]) -> None:
    # TODO: Normalize enum names, and fix potentially invalid enum names

    existing_type = bv.types.get(enum_name)
    if existing_type is None:
        # Create a new enum
        with EnumerationBuilder.builder(bv, enum_name) as new_enum:
            for enum_value_name, enum_value in hash_list:
                new_enum.append(enum_value_name, enum_value)
    else:
        # Modify an existing enum
        if existing_type.type_class == TypeClass.EnumerationTypeClass:
            with Type.builder(bv, enum_name) as existing_enum:
                # In Binary Ninja, enumeration members are not guaranteed to be unique.
                # It is possible to have 2 different enum members
                # with exactly the same name and the same value.
                # Therefore, we must take care to _replace_ any existing enum member
                # with the same name as the enum member we would like to add,
                # rather than _appending_ a duplicate member with the same name.

                # Create a list of member names to use for lookup.
                # EnumerationBuilder.replace requires a member index as an argument,
                # so we must save the original member index as well.
                member_dict = {
                    member.name: idx for (idx, member) in enumerate(existing_enum.members)
                }

                for enum_value_name, enum_value in hash_list:
                    if enum_value_name in member_dict:
                        existing_enum.replace(
                            member_dict.get(enum_value_name), # original member idx
                            enum_value_name, # new name
                            enum_value, # new value
                        )
                        # TODO: It's possible here that the user would like to
                        # always ignore any duplicate enum members,
                        # rather than always replacing them.
                        # Consider how to handle this in the future.
                    else:
                        # Enum member with this name doesn't yet exist
                        existing_enum.append(
                            enum_value_name, # new name
                            enum_value, # new value
                        )
        else:
            logger.log_error(f"Enum values could not be added; a non-enum type with the name {enum_name} already exists.")

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