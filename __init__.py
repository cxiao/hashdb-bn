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
## Maintained by Cindy Xiao <contact@cxiao.net>
## Originally rewritten for Binary Ninja by @psifertex
## Original IDA plugin by @herrcore
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
##          Test IAT creation method
##          Use new Workflows API to re-write function calls to the import
##
########################################################################################

import json
from typing import List, Tuple

from binaryninja.log import Logger
from binaryninja.settings import Settings
from binaryninjaui import Menu, UIAction, UIActionHandler  # type: ignore

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
# The algorithm setting will be serialized into each analysis
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
            "title": "HashDB Enum Name",
            "type": "string",
            "default": DEFAULT_ENUM_NAME,
            "description": "Name of enum used for HashDB strings",
            "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
        },
    ),
    (
        "hashdb.algorithm",
        {
            "title": "HashDB Hash Algorithm",
            "type": "string",
            "optional": True,
            "description": "Hash algorithm used for the current binary. This setting is specific to a particular analysis database.",
            "ignore": ["SettingsUserScope", "SettingsProjectScope"],
        },
    ),
    (
        "hashdb.algorithm_type",
        {
            "title": "HashDB Hash Algorithm Data Type",
            "type": "string",
            "optional": True,
            "enum": ["unsigned_int", "unsigned_long"],
            "enumDescriptions": ["unsigned int (4 bytes)", "unsigned long (8 bytes)"],
            "description": "Data type and data size of the hash algorithm used for the current binary. This setting is specific to a particular analysis database.",
            "ignore": ["SettingsUserScope", "SettingsProjectScope"],
        },
    ),
]


def register_settings() -> bool:
    Settings().register_group("hashdb", "HashDB")
    for setting_name, setting_properties in HASHDB_PLUGIN_SETTINGS:
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
    version = 0
    try:
        from binaryninja import core_version_info
        version = core_version_info().build
    except:
        # can be removed whenever min build of the plugin is >= 3814
        from binaryninja import core_version
        version = core_version()
        if version:
            version = int(version[4:][:4])
    if version >= 3505 or version == 0: #internal dev builds show 0
        parent_menu = "Plugins"
    return parent_menu


if not register_settings():
    logger.log_error("Failed to initialize HashDB plugin settings")


def context_menu_creator(context):
    # This is a hack which uses the `isValid` callback
    # (which can be passed to the constructor of a UIAction)
    # in order to register the HashDB actions in the context menu.
    # This method is taken from the Tanto plugin:
    # https://github.com/Vector35/tanto/blob/09d5873c85e65458a4e99b45b82c7f22167345ee/__init__.py#L770

    if context is not None:
        view = context.view
        if view is not None:
            context_menu = view.contextMenu()

            if len(context_menu.getActions().keys()) == 0:
                return context.context and context.binaryView

            context_menu.addAction(f"HashDB\\Hash Lookup", "", 0)
            context_menu.addAction(f"HashDB\\Multiple Hash Lookup", "", 1)
            context_menu.addAction(f"HashDB\\Hunt", "", 2)
            context_menu.addAction(f"HashDB\\Select Hash Algorithm...", "", 3)
            return context.context and context.binaryView
    else:
        return False


for action, target, add_to_menu in [
    ["HashDB\\Hash Lookup", actions.hash_lookup, False],
    ["HashDB\\Multiple Hash Lookup", actions.multiple_hash_lookup, False],
    ["HashDB\\Hunt", actions.hunt_algorithm, False],
    ["HashDB\\Select Hash Algorithm...", actions.select_hash_algorithm, True],
]:
    UIAction.registerAction(action)
    UIActionHandler.globalActions().bindAction(
        action, UIAction(target, context_menu_creator)
    )
    if add_to_menu:
        Menu.mainMenu(plugin_parent_menu()).addAction(action, "HashDB")
