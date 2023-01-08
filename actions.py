from typing import cast, Dict, List, Optional, Union
from functools import partial

from binaryninja import BinaryReader, BinaryView, interaction
from binaryninja.enums import InstructionTextTokenType, TypeClass
from binaryninja.log import Logger
from binaryninja.mainthread import (
    execute_on_main_thread,
    execute_on_main_thread_and_wait,
)
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.settings import Settings, SettingsScope
from binaryninja.types import EnumerationBuilder, Type, QualifiedName
from binaryninjaui import UIActionContext  # type: ignore

from . import hashdb_api as api

logger = Logger(session_id=0, logger_name=__name__)


# --------------------------------------------------------------------------
# Set xor key
# --------------------------------------------------------------------------
def set_xor_key(context: UIActionContext) -> bool:
    """
    Set xor key from selection
    """
    bv = context.binaryView
    token = context.token.token
    if token and token.type == InstructionTextTokenType.IntegerToken:
        if token.text.startswith("-"):
            # Handle negatives later
            logger.log_warn("plugin does not currently handle negative values.")
            return False
        xor_value = token.value
        Settings().set_integer(
            "hashdb.xor_value", xor_value, SettingsScope.SettingsResourceScope
        )
        logger.log_info(f"XOR key set: {xor_value:#x}")
        return True
    else:
        logger.log_info(f"failed to set XOR key.")
        return False


# --------------------------------------------------------------------------
# Hash lookup
# --------------------------------------------------------------------------
class HashLookupTask(BackgroundTaskThread):
    def __init__(
        self,
        bv: BinaryView,
        hashdb_api_url: str,
        hashdb_enum_name: str,
        hashdb_algorithm: str,
        hashdb_xor_value: int,
        hash_value: int,
    ):
        super().__init__(
            initial_progress_text="[HashDB] Hash lookup task starting...",
            can_cancel=False,
        )

        self.bv = bv
        self.hashdb_api_url = hashdb_api_url
        self.hashdb_enum_name = hashdb_enum_name
        self.hashdb_algorithm = hashdb_algorithm
        self.hashdb_xor_value = hashdb_xor_value
        self.hash_value = hash_value

    def run(self):
        hash_results = self.call_api_get_strings_from_hash(
            self.hashdb_api_url, self.hashdb_algorithm, self.hash_value
        )
        hash_string: api.HashString

        if hash_results is None or len(hash_results) == 0:
            logger.log_warn(f"No hash found for value {self.hash_value:#x}")
            self.progress = f"[HashDB] Hash lookup finished; no hash found for value {self.hash_value:#x}"
            self.finish()
            return
        elif len(hash_results) == 1:
            hash_string = hash_results[0].hash_string
        else:
            self.progress = f"[HashDB] Multiple hash results found; choose a hash..."
            output_user_choose_hash_from_collisions: List[Optional[api.HashString]] = [
                None
            ]
            user_choose_hash_from_collisions_fn = partial(
                self.user_choose_hash_from_collisions,
                hash_results,
                output_hash_string=output_user_choose_hash_from_collisions,
            )
            execute_on_main_thread_and_wait(user_choose_hash_from_collisions_fn)
            hash_string = output_user_choose_hash_from_collisions[0]
            self.progress = ""

        if hash_string.is_api and hash_string.modules is not None:
            self.progress = f"[HashDB] Hash found is an API string which is part of a module; choose whether to import the module..."
            output_user_choose_module_import: List[Optional[str]] = [None]
            user_choose_module_fn = partial(
                self.user_choose_module_import,
                hash_string.get_api_string_if_available(),
                hash_string.modules,
                output_module_name=output_user_choose_module_import,
            )
            execute_on_main_thread_and_wait(user_choose_module_fn)
            module_to_import = output_user_choose_module_import[0]
            self.progress = ""

            logger.log_debug(
                f"user chose module with name {module_to_import} to import from list {hash_string.modules}"
            )
            if module_to_import is not None and hash_string.permutation is not None:
                module_hash_list = self.call_api_get_module_hashes(
                    self.hashdb_api_url,
                    self.hashdb_algorithm,
                    module_to_import,
                    hash_string.permutation,
                )
                logger.log_debug(
                    f"hash_lookup obtained module hash list: {module_hash_list}"
                )
                if module_hash_list is not None:
                    self.add_enums(self.bv, self.hashdb_enum_name, module_hash_list)
                    self.bv.update_analysis_and_wait()
        else:  # Simple case, not an API which may be part of a module; just add a single hash to the enum
            self.add_enums(
                self.bv, self.hashdb_enum_name, [api.Hash(self.hash_value, hash_string)]
            )
            self.bv.update_analysis_and_wait()
        self.finish()
        return

    def call_api_get_strings_from_hash(
        self, hashdb_api_url: str, hashdb_algorithm: str, hash_value: int
    ) -> Optional[List[api.Hash]]:
        try:
            hash_results = api.get_strings_from_hash(
                hashdb_algorithm,
                hash_value,
                hashdb_api_url,
            )
            return hash_results
        except api.HashDBError as api_error:
            logger.log_error(f"HashDB API request failed: {api_error}")
            return None

    def call_api_get_module_hashes(
        self,
        hashdb_api_url: str,
        hashdb_algorithm: str,
        module_name: str,
        permutation: str,
    ) -> Optional[List[api.Hash]]:
        try:
            module_hash_results = api.get_module_hashes(
                module_name,
                hashdb_algorithm,
                permutation,
                hashdb_api_url,
            )
            return module_hash_results
        except api.HashDBError as api_error:
            logger.log_error(f"HashDB API request failed: {api_error}")
            return None

    def user_choose_hash_from_collisions(
        self,
        hash_candidates: List[api.Hash],
        output_hash_string: List[Optional[api.HashString]],
    ):
        # Multiple hashes found
        # Allow the user to select the best match
        collisions: Dict[str, api.HashString] = {}
        for hash_candidate in hash_candidates:
            collisions[
                hash_candidate.hash_string.get_api_string_if_available()
            ] = hash_candidate.hash_string

        choice_idx = interaction.get_choice_input(
            "Select the best match: ", "String Selection", list(collisions.keys())
        )
        if choice_idx is not None:
            choice = list(collisions.keys())[choice_idx]
        else:
            # User cancelled, select the first one?
            choice = list(collisions.keys())[0]

        output_hash_string[0] = collisions[choice]

    def user_choose_module_import(
        self,
        resolved_string_value: str,
        modules: List[str],
        output_module_name: List[Optional[str]],
    ):
        modules.sort()
        choice_idx = interaction.get_choice_input(
            f"The hash for {resolved_string_value} is a module function.\n\nDo you want to import all function hashes from this module?",
            "HashDB Bulk Import",
            modules,
        )
        if choice_idx is not None:
            module_name = modules[choice_idx]
            logger.log_debug(f"{choice_idx}: {module_name}")
            output_module_name[0] = module_name
        else:
            output_module_name[0] = None

    def add_enums(
        self, bv: BinaryView, enum_name: str, hash_list: List[api.Hash]
    ) -> None:
        existing_type = bv.types.get(enum_name)
        if existing_type is None:
            # Create a new enum
            with EnumerationBuilder.builder(bv, QualifiedName(enum_name)) as new_enum:
                new_enum = cast(EnumerationBuilder, new_enum)  # typing
                for hash_ in hash_list:
                    enum_value_name = hash_.hash_string.get_api_string_if_available()
                    enum_value = hash_.value
                    new_enum.append(enum_value_name, enum_value)
        else:
            # Modify an existing enum
            if existing_type.type_class == TypeClass.EnumerationTypeClass:
                with Type.builder(bv, QualifiedName(enum_name)) as existing_enum:
                    existing_enum = cast(EnumerationBuilder, existing_enum)  # typing
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
                        member.name: idx
                        for (idx, member) in enumerate(existing_enum.members)
                    }

                    for hash_ in hash_list:
                        enum_value_name = (
                            hash_.hash_string.get_api_string_if_available()
                        )
                        enum_value = hash_.value
                        enum_member_idx = member_dict.get(enum_value_name)
                        if enum_member_idx is not None:
                            existing_enum.replace(
                                enum_member_idx,  # original member idx
                                enum_value_name,  # new name
                                enum_value,  # new value
                            )
                        else:
                            # Enum member with this name doesn't yet exist
                            existing_enum.append(
                                enum_value_name,  # new name
                                enum_value,  # new value
                            )
            else:
                logger.log_error(
                    f"Enum values could not be added; a non-enum type with the name {enum_name} already exists."
                )


def hash_lookup(context: UIActionContext) -> None:
    """
    Lookup hash from highlighted text
    """
    bv = context.binaryView
    token = context.token.token

    hashdb_api_url = Settings().get_string("hashdb.url")
    if hashdb_api_url is None or hashdb_api_url == "":
        logger.log_error("HashDB API URL not found.")
        return

    hashdb_enum_name = Settings().get_string_with_scope("hashdb.enum_name", bv)[0]
    if hashdb_enum_name is None or hashdb_enum_name == "":
        logger.log_error("HashDB enum name not found.")
        return

    hashdb_algorithm = Settings().get_string_with_scope("hashdb.algorithm", bv)[0]
    if hashdb_algorithm is None or hashdb_algorithm == "":
        interaction.show_message_box(
            "[HashDB] Algorithm selection required",
            "[HashDB] Please select an algorithm before looking up a hash.\n\nYou can hunt for the correct algorithm for a hash by using the HashDB > Hunt command.",
        )
        logger.log_warn("Algorithm selection is required before looking up hashes.")
        return

    hashdb_xor_value = Settings().get_integer_with_scope(
        "hashdb.xor_value", bv, SettingsScope.SettingsResourceScope
    )[0]

    if token and token.type == InstructionTextTokenType.IntegerToken:
        if token.text.startswith("-"):
            # Handle negatives later
            logger.log_warn("plugin does not currently handle negative values.")
            return
        hash_value = token.value
        hash_value ^= hashdb_xor_value

        HashLookupTask(
            bv=bv,
            hashdb_api_url=hashdb_api_url,
            hashdb_enum_name=hashdb_enum_name,
            hashdb_algorithm=hashdb_algorithm,
            hashdb_xor_value=hashdb_xor_value,
            hash_value=hash_value,
        ).start()


def change_hash_algorithm(context) -> None:
    Settings().reset(
        "hashdb.algorithm", context.binaryView, SettingsScope.SettingsResourceScope
    )
    select_hash_algorithm(context.binaryView)


# --------------------------------------------------------------------------
# Ask for a hash algorithm
# --------------------------------------------------------------------------
def select_hash_algorithm(bv: BinaryView) -> Optional[str]:
    hashdb_api_url = Settings().get_string("hashdb.url")
    if hashdb_api_url is None:
        logger.log_error("HashDB API URL not found.")
        return

    hashdb_algorithm = Settings().get_string_with_scope(
        "hashdb.algorithm", bv, SettingsScope.SettingsResourceScope
    )[0]

    if hashdb_algorithm is None or hashdb_algorithm == "":
        try:
            algorithms = api.get_algorithms(hashdb_api_url)
        except api.HashDBError as api_error:
            logger.log_error(f"HashDB API request failed: {api_error}")
            return None

        algorithm_choice = interaction.get_choice_input(
            "Select an algorithm:", "Algorithms", algorithms
        )
        if algorithm_choice is not None:
            result = algorithms[algorithm_choice].algorithm
            Settings().set_string(
                key="hashdb.algorithm",
                value=result,
                view=bv,
                scope=SettingsScope.SettingsResourceScope,
            )
            return result
        else:
            return None
    else:
        return hashdb_algorithm


# --------------------------------------------------------------------------
# Dynamic IAT hash scan
# --------------------------------------------------------------------------
class MultipleHashLookupTask(BackgroundTaskThread):
    def __init__(
        self,
        bv: BinaryView,
        hashdb_api_url: str,
        hashdb_enum_name: str,
        hashdb_algorithm: str,
        hashdb_xor_value: int,
        hash_values: List[int],
    ):
        super().__init__(
            initial_progress_text="[HashDB] Hash scan task starting...",
            can_cancel=False,
        )

        self.bv = bv
        self.hashdb_api_url = hashdb_api_url
        self.hashdb_enum_name = hashdb_enum_name
        self.hashdb_algorithm = hashdb_algorithm
        self.hashdb_xor_value = hashdb_xor_value
        self.hash_values = hash_values

    def run(self):
        collected_hash_values: List[Union[List[api.Hash], api.HashDBError]] = []
        collected_hash_values = api.get_strings_from_hashes(
            self.hashdb_algorithm, self.hash_values, self.hashdb_api_url
        )

        for collected_hash_value in collected_hash_values:
            if isinstance(collected_hash_value, api.HashDBError):
                logger.log_error(f"HashDB API request failed: {collected_hash_value}")
                self.finish()
                return
            elif isinstance(collected_hash_value, List):
                if len(collected_hash_value) == 0:
                    self.finish()
                    return
                if len(collected_hash_value) == 1:
                    self.add_enums(self.bv, self.hashdb_enum_name, collected_hash_value)
                    self.bv.update_analysis_and_wait()
                else:
                    output_user_choose_hash_from_collisions: List[
                        Optional[api.HashString]
                    ] = [None]
                    user_choose_hash_from_collisions_fn = partial(
                        self.user_choose_hash_from_collisions,
                        collected_hash_value,
                        output_hash_string=output_user_choose_hash_from_collisions,
                    )
                    execute_on_main_thread_and_wait(user_choose_hash_from_collisions_fn)
                    hash_string = output_user_choose_hash_from_collisions[0]

                    if hash_string is not None:
                        self.add_enums(
                            self.bv,
                            self.hashdb_enum_name,
                            [api.Hash(collected_hash_value[0].value, hash_string)],
                        )
                        self.bv.update_analysis_and_wait()

        self.finish()
        return

    def user_choose_hash_from_collisions(
        self,
        hash_candidates: List[api.Hash],
        output_hash_string: List[Optional[api.HashString]],
    ):
        # Multiple hashes found
        # Allow the user to select the best match
        collisions: Dict[str, api.HashString] = {}
        for hash_candidate in hash_candidates:
            collisions[
                hash_candidate.hash_string.get_api_string_if_available()
            ] = hash_candidate.hash_string

        choice_idx = interaction.get_choice_input(
            "Select the best match: ", "String Selection", list(collisions.keys())
        )
        if choice_idx is not None:
            choice = list(collisions.keys())[choice_idx]
        else:
            # User cancelled, select the first one?
            choice = list(collisions.keys())[0]

        output_hash_string[0] = collisions[choice]

    def add_enums(
        self, bv: BinaryView, enum_name: str, hash_list: List[api.Hash]
    ) -> None:
        existing_type = bv.types.get(enum_name)
        if existing_type is None:
            # Create a new enum
            with EnumerationBuilder.builder(bv, QualifiedName(enum_name)) as new_enum:
                new_enum = cast(EnumerationBuilder, new_enum)  # typing
                for hash_ in hash_list:
                    enum_value_name = hash_.hash_string.get_api_string_if_available()
                    enum_value = hash_.value
                    new_enum.append(enum_value_name, enum_value)
        else:
            # Modify an existing enum
            if existing_type.type_class == TypeClass.EnumerationTypeClass:
                with Type.builder(bv, QualifiedName(enum_name)) as existing_enum:
                    existing_enum = cast(EnumerationBuilder, existing_enum)  # typing
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
                        member.name: idx
                        for (idx, member) in enumerate(existing_enum.members)
                    }

                    for hash_ in hash_list:
                        enum_value_name = (
                            hash_.hash_string.get_api_string_if_available()
                        )
                        enum_value = hash_.value
                        enum_member_idx = member_dict.get(enum_value_name)
                        if enum_member_idx is not None:
                            existing_enum.replace(
                                enum_member_idx,  # original member idx
                                enum_value_name,  # new name
                                enum_value,  # new value
                            )
                        else:
                            # Enum member with this name doesn't yet exist
                            existing_enum.append(
                                enum_value_name,  # new name
                                enum_value,  # new value
                            )
            else:
                logger.log_error(
                    f"Enum values could not be added; a non-enum type with the name {enum_name} already exists."
                )

    def call_api_get_strings_from_hash(
        self, hashdb_api_url: str, hashdb_algorithm: str, hash_value: int
    ) -> Optional[List[api.Hash]]:
        try:
            hash_results = api.get_strings_from_hash(
                hashdb_algorithm,
                hash_value,
                hashdb_api_url,
            )
            return hash_results
        except api.HashDBError as api_error:
            logger.log_error(f"HashDB API request failed: {api_error}")
            return None


def multiple_hash_lookup(context: UIActionContext) -> None:
    """
    Lookup hash from highlighted text
    """
    bv = context.binaryView

    hashdb_api_url = Settings().get_string("hashdb.url")
    if hashdb_api_url is None or hashdb_api_url == "":
        logger.log_error("HashDB API URL not found.")
        return

    hashdb_enum_name = Settings().get_string_with_scope("hashdb.enum_name", bv)[0]
    if hashdb_enum_name is None or hashdb_enum_name == "":
        logger.log_error("HashDB enum name not found.")
        return

    hashdb_algorithm = Settings().get_string_with_scope("hashdb.algorithm", bv)[0]
    if hashdb_algorithm is None or hashdb_algorithm == "":
        interaction.show_message_box(
            "[HashDB] Algorithm selection required",
            "[HashDB] Please select an algorithm before looking up a hash.\n\nYou can hunt for the correct algorithm for a hash by using the HashDB > Hunt command.",
        )
        logger.log_warn("Algorithm selection is required before looking up hashes.")
        return

    hashdb_xor_value = Settings().get_integer_with_scope(
        "hashdb.xor_value", bv, SettingsScope.SettingsResourceScope
    )[0]

    try:
        br = BinaryReader(bv, bv.endianness)
        br.seek(context.address)

        selected_integer_values = []
        selected_address_range_end = br.offset
        while br.offset < (context.address + context.length):
            selected_integer_value = br.read32()
            if selected_integer_value is not None:
                selected_integer_values.append(selected_integer_value)
                selected_address_range_end = br.offset
            else:
                logger.log_warn(
                    f"Could not read value at address {br.offset:#x} as 32-bit integer; only submitting hashes read up to this address for analysis."
                )
                break

        logger.log_info(
            f"Found {len(selected_integer_values)} 32-bit integer values which are potential hashes, from address {context.address:#x} to {selected_address_range_end:#x}. Submitting values..."
        )
        for selected_integer_value in selected_integer_values:
            logger.log_debug(f"Found value {selected_integer_value:#x}")

        MultipleHashLookupTask(
            bv=bv,
            hashdb_api_url=hashdb_api_url,
            hashdb_enum_name=hashdb_enum_name,
            hashdb_algorithm=hashdb_algorithm,
            hashdb_xor_value=hashdb_xor_value,
            hash_values=selected_integer_values,
        ).start()

    except Exception as err:
        logger.log_error("Error trying to read highlighted text: {err}")


# --------------------------------------------------------------------------
# Algorithm search function
# --------------------------------------------------------------------------
class HuntAlgorithmTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, hashdb_api_url: str, hash_value: int):
        super().__init__(
            initial_progress_text="[HashDB] Algorithm hunt task starting...",
            can_cancel=False,
        )
        self.bv = bv
        self.hashdb_api_url = hashdb_api_url
        self.hash_value = hash_value

    def run(self):
        match_results = self.call_api(self.hashdb_api_url, self.hash_value)
        if match_results is None or len(match_results) == 0:
            interaction.show_message_box("No Match", "No algorithms matched the hash.")
        else:
            user_choose_match_fn = partial(self.user_choose_match, match_results)
            execute_on_main_thread(user_choose_match_fn)
        self.finish()
        return

    def call_api(
        self, hashdb_api_url: str, hash_value: int
    ) -> Optional[List[api.HuntMatch]]:
        try:
            match_results = api.hunt_hash(
                hash_value,
                hashdb_api_url,
            )
            return match_results
        except api.HashDBError as api_error:
            logger.log_error(f"HashDB API request failed: {api_error}")
            return None

    def user_choose_match(self, match_results: List[api.HuntMatch]) -> None:
        msg = """The following algorithms contain a matching hash.
            Select an algorithm to set as the default for this binary."""
        choice_idx = interaction.get_choice_input(msg, "Select a hash", match_results)
        if choice_idx is not None:
            Settings().set_string(
                key="hashdb.algorithm",
                value=match_results[choice_idx].algorithm,
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )
        else:
            logger.log_warn("No hash algorithm selected.")


def hunt_algorithm(context: UIActionContext) -> None:
    bv = context.binaryView

    hashdb_api_url = Settings().get_string("hashdb.url")
    if hashdb_api_url is None:
        logger.log_error("HashDB API URL not found.")
        return

    hashdb_enum_name = Settings().get_string_with_scope("hashdb.enum_name", bv)[0]
    if hashdb_enum_name is None:
        logger.log_error("HashDB enum name not found.")
        return

    hashdb_xor_value = Settings().get_integer_with_scope(
        "hashdb.xor_value", bv, SettingsScope.SettingsResourceScope
    )[0]

    # Get selected hash
    token = context.token.token
    if token and token.type == InstructionTextTokenType.IntegerToken:
        if token.text.startswith("-"):
            # Handle negatives later
            logger.log_warn("plugin does not currently handle negative values.")
            return
        hash_value = token.value
        hash_value ^= hashdb_xor_value
        HuntAlgorithmTask(bv, hashdb_api_url, hash_value).start()
    else:
        logger.log_warn("This token does not look like a valid integer.")
