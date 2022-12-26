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

import json
from typing import List, Tuple

from binaryninja import core_version
from binaryninja.log import Logger
from binaryninja.settings import Settings
from binaryninjaui import Menu, UIAction, UIActionHandler # type: ignore

from . import actions

logger = Logger(session_id=0, logger_name=__name__)

# --------------------------------------------------------------------------
# Global settings
# --------------------------------------------------------------------------

# Using a global setting for the URL and enum_name so it can be changed
# system-wide and replacing the global variable with the settings API so
# they can be changed on the fly without having to reload the plugin ur
# use a distinct settings system.
#
# The xor and alg setting will be serialized into each analysis
# database's metadata, by always using the `SettingsResourceScope`
# for those settings.

DEFAULT_ENUM_NAME = "hashdb_strings"
DEFAULT_API_URL = "https://hashdb.openanalysis.net"
HASHDB_PLUGIN_SETTINGS: List[Tuple[str, dict]] = [
    (
        "hashdb.url",
        {
            "title": "HashDB API URL",
            "type": "string",
            "default": DEFAULT_API_URL,
            "description": "URL of the server used to query HashDB",
            "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
        },
    ),
    (
        "hashdb.enum_name",
        {
            "title": "Name of enum used for HashDB strings",
            "type": "string",
            "default": DEFAULT_ENUM_NAME,
            "description": "",
            "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
        },
    ),
    (
        "hashdb.xor_value",
        {
            "title": "XOR key to apply to hash values",
            "type": "number",
            "default": 0,
            "description": "",
            "ignore": ["SettingsUserScope", "SettingsProjectScope"],
        },
    ),
    (
        "hashdb.algorithm",
        {
            "title": "Hash algorithm used by this database",
            "type": "string",
            "optional": True,
            "description": "",
            "ignore": ["SettingsUserScope", "SettingsProjectScope"],
        },
    ),
]


def register_settings() -> bool:
    Settings().register_group("hashdb", "Open Analysis HashDB")
    for (setting_name, setting_properties) in HASHDB_PLUGIN_SETTINGS:
        if not Settings().register_setting(
            setting_name, json.dumps(setting_properties)
        ):
            logger.log_error(
                f"Failed to register setting with name {setting_name}, properties {setting_properties}"
            )
            logger.log_error(f"Abandoning setting registration")
            return False
    return True


# --------------------------------------------------------------------------
# Plugin Registration
# --------------------------------------------------------------------------
def plugin_parent_menu() -> str:
    parent_menu = "Tools"
    version = core_version()
    if version and int(version[4:][:4]) >= 3505:
        parent_menu = "Plugins"
    return parent_menu


if not register_settings():
    logger.log_error("Failed to initialize HashDB plugin settings")

for (action, target, add_to_menu) in [
    ["HashDB\\Hash Lookup", actions.hash_lookup, False],
    ["HashDB\\Set Xor...", actions.set_xor_key, False],
    ["HashDB\\Hunt", actions.hunt_algorithm, False],
    ["HashDB\\IAT Scan", actions.hash_scan, True],
    ["HashDB\\Reset Hash", actions.change_hash_algorithm, True],
]:
    UIAction.registerAction(action)
    UIActionHandler.globalActions().bindAction(action, UIAction(target))
    if add_to_menu:
        Menu.mainMenu(plugin_parent_menu()).addAction(action, "HashDB")
