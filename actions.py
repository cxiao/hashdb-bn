from typing import cast, Dict, List, Optional, Union, Tuple
from functools import partial
import struct

from binaryninja import BinaryReader, BinaryView, interaction
from binaryninja.enums import Endianness, InstructionTextTokenType, TypeClass
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


def add_enums(
    bv: BinaryView, enum_name: str, enum_width: int, hash_list: List[api.Hash]
) -> None:
    existing_type = bv.types.get(enum_name)
    if existing_type is None:
        # Create a new enum
        new_enum = EnumerationBuilder.create(width=enum_width)
        for hash_ in hash_list:
            enum_value_name = hash_.hash_string.get_api_string_if_available()
            enum_value = hash_.value
            new_enum.append(enum_value_name, enum_value)
        bv.define_user_type(name=QualifiedName(enum_name), type_obj=new_enum)
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
                    enum_value_name = hash_.hash_string.get_api_string_if_available()
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
        hashdb_algorithm_data_width: int,
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
        self.hashdb_algorithm_data_width = hashdb_algorithm_data_width
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
                    add_enums(
                        bv=self.bv,
                        enum_name=self.hashdb_enum_name,
                        enum_width=self.hashdb_algorithm_data_width,
                        hash_list=module_hash_list,
                    )
                    self.bv.update_analysis_and_wait()

        add_enums(
            bv=self.bv,
            enum_name=self.hashdb_enum_name,
            enum_width=self.hashdb_algorithm_data_width,
            hash_list=[api.Hash(self.hash_value, hash_string)],
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
            "Select the best match: ",
            "[HashDB] String Selection",
            list(collisions.keys()),
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
            title="[HashDB] Bulk Import",
            prompt=f"The hash for {resolved_string_value} is a module function.\n\nDo you want to import all function hashes from this module?",
            choices=modules,
        )
        if choice_idx is not None:
            module_name = modules[choice_idx]
            logger.log_debug(f"{choice_idx}: {module_name}")
            output_module_name[0] = module_name
        else:
            output_module_name[0] = None


def hash_lookup(context: UIActionContext) -> None:
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
            "[HashDB] Algorithm Selection Required",
            "Please select an algorithm before looking up a hash.\n\nYou can hunt for the correct algorithm for a hash by using the HashDB > Hunt command.",
        )
        logger.log_warn("Algorithm selection is required before looking up hashes.")
        return

    hashdb_algorithm_data_type = Settings().get_string_with_scope(
        "hashdb.algorithm_type", bv
    )[0]
    if hashdb_algorithm_data_type is None or hashdb_algorithm_data_type == "":
        logger.log_error("HashDB algorithm data type not found.")
        return
    hashdb_algorithm_data_type = api.AlgorithmType.from_raw_name(
        hashdb_algorithm_data_type
    )

    if context.token.token:
        token = context.token.token
        if token.type == InstructionTextTokenType.IntegerToken:
            if token.text.startswith("-"):
                # Handle negatives later
                logger.log_warn("plugin does not currently handle negative values.")
                return
            hash_value = token.value

            HashLookupTask(
                bv=bv,
                hashdb_api_url=hashdb_api_url,
                hashdb_enum_name=hashdb_enum_name,
                hashdb_algorithm=hashdb_algorithm,
                hashdb_algorithm_data_width=hashdb_algorithm_data_type.size,
                hash_value=hash_value,
            ).start()
        else:
            logger.log_error(
                f"Could not look up hash: the selected token `{token.text}` does not look like a valid integer."
            )
    else:
        # No token available; try reading a selection from the context instead
        br = BinaryReader(bv, bv.endianness)
        selected_integer_bytes = br.read(length=context.length, address=context.address)
        selected_integer_value: Optional[int] = None

        if selected_integer_bytes is not None:
            if hashdb_algorithm_data_type.size == 4:
                try:
                    if br.endianness == Endianness.LittleEndian:
                        selected_integer_value = struct.unpack(
                            "<I", selected_integer_bytes
                        )[0]
                    elif br.endianness == Endianness.BigEndian:
                        selected_integer_value = struct.unpack(
                            ">I", selected_integer_bytes
                        )[0]
                except struct.error as err:
                    logger.log_error(
                        f"Could not interpret selection as a 32-bit integer: {err}"
                    )
            elif hashdb_algorithm_data_type.size == 8:
                if len(selected_integer_bytes) == 4:
                    try:
                        if br.endianness == Endianness.LittleEndian:
                            selected_integer_value = struct.unpack(
                                "<I", selected_integer_bytes
                            )[0]
                        elif br.endianness == Endianness.BigEndian:
                            selected_integer_value = struct.unpack(
                                ">I", selected_integer_bytes
                            )[0]
                    except struct.error as err:
                        logger.log_error(
                            f"Could not interpret selection as a 32-bit integer: {err}"
                        )
                elif len(selected_integer_bytes) == 8:
                    try:
                        if br.endianness == Endianness.LittleEndian:
                            selected_integer_value = struct.unpack(
                                "<Q", selected_integer_bytes
                            )[0]
                        elif br.endianness == Endianness.BigEndian:
                            selected_integer_value = struct.unpack(
                                ">Q", selected_integer_bytes
                            )[0]
                    except struct.error as err:
                        logger.log_error(
                            f"Could not interpret selection as a 64-bit integer: {err}"
                        )

        if selected_integer_value is not None:
            logger.log_debug(f"Found value {selected_integer_value:#x}")
            HashLookupTask(
                bv=bv,
                hashdb_api_url=hashdb_api_url,
                hashdb_enum_name=hashdb_enum_name,
                hashdb_algorithm=hashdb_algorithm,
                hashdb_algorithm_data_width=hashdb_algorithm_data_type.size,
                hash_value=selected_integer_value,
            ).start()


# --------------------------------------------------------------------------
# Ask for a hash algorithm
# --------------------------------------------------------------------------
def select_hash_algorithm(context: UIActionContext) -> None:
    bv = context.binaryView

    hashdb_api_url = Settings().get_string("hashdb.url")
    if hashdb_api_url is None or hashdb_api_url == "":
        logger.log_error("HashDB API URL not found.")
        return

    try:
        algorithms = api.get_algorithms(hashdb_api_url)
    except api.HashDBError as api_error:
        logger.log_error(f"HashDB API request failed: {api_error}")
        return None

    prompt_text_current_algorithm = Settings().get_string_with_scope(
        "hashdb.algorithm", bv
    )[0]
    if prompt_text_current_algorithm is None or prompt_text_current_algorithm == "":
        prompt_text_current_algorithm = "None"
    prompt_text = f"Select an algorithm from the list of known algorithms below.\nIf you are not sure which algorithm is correct, you can try selecting a value and hunting for a matching algorithm via the HashDB > Hunt action instead.\n\nThe currently set algorithm is `{prompt_text_current_algorithm}`."

    algorithm_choice = interaction.get_choice_input(
        title="[HashDB] Algorithm Selection",
        prompt=prompt_text,
        choices=algorithms,
    )
    if algorithm_choice is not None:
        algorithm_name = algorithms[algorithm_choice].algorithm
        algorithm_data_type = algorithms[algorithm_choice].type.name
        Settings().set_string(
            key="hashdb.algorithm",
            value=algorithm_name,
            view=bv,
            scope=SettingsScope.SettingsResourceScope,
        )
        Settings().set_string(
            key="hashdb.algorithm_type",
            value=algorithm_data_type,
            view=bv,
            scope=SettingsScope.SettingsResourceScope,
        )


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
        hashdb_algorithm_data_width: int,
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
        self.hashdb_algorithm_data_width = hashdb_algorithm_data_width
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
                    add_enums(
                        bv=self.bv,
                        enum_name=self.hashdb_enum_name,
                        enum_width=self.hashdb_algorithm_data_width,
                        hash_list=collected_hash_value,
                    )
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
                        add_enums(
                            bv=self.bv,
                            enum_name=self.hashdb_enum_name,
                            enum_width=self.hashdb_algorithm_data_width,
                            hash_list=[
                                api.Hash(collected_hash_value[0].value, hash_string)
                            ],
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
            "Select the best match: ",
            "[HashDB] String Selection",
            list(collisions.keys()),
        )
        if choice_idx is not None:
            choice = list(collisions.keys())[choice_idx]
        else:
            # User cancelled, select the first one?
            choice = list(collisions.keys())[0]

        output_hash_string[0] = collisions[choice]

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
            "[HashDB] Algorithm Selection Required",
            "Please select an algorithm before looking up a hash.\n\nYou can hunt for the correct algorithm for a hash by using the HashDB > Hunt command.",
        )
        logger.log_warn("Algorithm selection is required before looking up hashes.")
        return

    hashdb_algorithm_data_type = Settings().get_string_with_scope(
        "hashdb.algorithm_type", bv
    )[0]
    if hashdb_algorithm_data_type is None or hashdb_algorithm_data_type == "":
        logger.log_error("HashDB algorithm data type not found.")
        return
    hashdb_algorithm_data_type = api.AlgorithmType.from_raw_name(
        hashdb_algorithm_data_type
    )

    try:
        br = BinaryReader(bv, bv.endianness)
        br.seek(context.address)

        selected_integer_values = []
        selected_address_range_end = br.offset
        while br.offset < (context.address + context.length):
            selected_integer_value = None
            if hashdb_algorithm_data_type.size == 4:
                selected_integer_value = br.read32()
            elif hashdb_algorithm_data_type.size == 8:
                selected_integer_value = br.read64()

            if selected_integer_value is not None:
                selected_integer_values.append(selected_integer_value)
                selected_address_range_end = br.offset
            else:
                logger.log_warn(
                    f"Could not read value at address {br.offset:#x} as {hashdb_algorithm_data_type.size}-byte integer; only submitting hashes read up to this address for analysis."
                )
                break

        logger.log_info(
            f"Found {len(selected_integer_values)} integer values which are potential hashes, from address {context.address:#x} to {selected_address_range_end:#x}. Submitting values..."
        )
        for selected_integer_value in selected_integer_values:
            logger.log_debug(f"Found value {selected_integer_value:#x}")

        MultipleHashLookupTask(
            bv=bv,
            hashdb_api_url=hashdb_api_url,
            hashdb_enum_name=hashdb_enum_name,
            hashdb_algorithm=hashdb_algorithm,
            hashdb_algorithm_data_width=hashdb_algorithm_data_type.size,
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
        match_results = self.call_hunt_api(self.hashdb_api_url, self.hash_value)
        if match_results is None or len(match_results) == 0:
            interaction.show_message_box(
                "[HashDB] No Match", "No algorithms matched the hash."
            )
        else:
            # The hunt API endpoint doesn't actually return any algorithm descriptions
            # or sizes, only their names; we must make another API request here to
            # get the remaining information.
            algorithm_list = self.call_algorithms_api(self.hashdb_api_url)
            if algorithm_list is not None:
                algorithm_dict = {
                    algorithm.algorithm: algorithm for algorithm in algorithm_list
                }
                match_results_with_algorithm_descriptions: List[
                    Tuple[api.HuntMatch, api.Algorithm]
                ] = [
                    (match_result, algorithm_dict[match_result.algorithm])
                    for match_result in match_results
                ]

                user_choose_match_fn = partial(
                    self.user_choose_match, match_results_with_algorithm_descriptions
                )
                execute_on_main_thread(user_choose_match_fn)
            else:
                logger.log_error("Could not retrieve a list of algorithm descriptions")
        self.finish()
        return

    def call_hunt_api(
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

    def call_algorithms_api(self, hashdb_api_url: str) -> Optional[List[api.Algorithm]]:
        try:
            algorithms = api.get_algorithms(hashdb_api_url)
            return algorithms
        except api.HashDBError as api_error:
            logger.log_error(f"HashDB API request failed: {api_error}")
            return None

    def user_choose_match(
        self,
        match_results: List[Tuple[api.HuntMatch, api.Algorithm]],
    ) -> None:
        displayed_match_results = [
            f"Count {hunt_match.count}, Hit rate {hunt_match.hitrate:.1%}: {algorithm}"
            for (hunt_match, algorithm) in match_results
        ]
        msg = """The following algorithms contain a matching hash.\n\nSelect an algorithm to set as the default for this binary."""
        choice_idx = interaction.get_choice_input(
            msg, "[HashDB] Algorithm Selection", displayed_match_results
        )
        if choice_idx is not None:
            (_hunt_match, chosen_algorithm) = match_results[choice_idx]
            algorithm_name = chosen_algorithm.algorithm
            algorithm_data_type = chosen_algorithm.type.name
            Settings().set_string(
                key="hashdb.algorithm",
                value=algorithm_name,
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )
            Settings().set_string(
                key="hashdb.algorithm_type",
                value=algorithm_data_type,
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )
        else:
            logger.log_warn("No hash algorithm selected.")


def hunt_algorithm(context: UIActionContext) -> None:
    bv = context.binaryView

    hashdb_api_url = Settings().get_string("hashdb.url")
    if hashdb_api_url is None or hashdb_api_url == "":
        logger.log_error("HashDB API URL not found.")
        return

    hashdb_enum_name = Settings().get_string_with_scope("hashdb.enum_name", bv)[0]
    if hashdb_enum_name is None or hashdb_enum_name == "":
        logger.log_error("HashDB enum name not found.")
        return

    if context.token.token:
        token = context.token.token
        if token.type == InstructionTextTokenType.IntegerToken:
            if token.text.startswith("-"):
                # Handle negatives later
                logger.log_warn("plugin does not currently handle negative values.")
                return
            hash_value = token.value
            HuntAlgorithmTask(bv, hashdb_api_url, hash_value).start()
        else:
            logger.log_error(
                f"Could not look up hash: the selected token `{token.text}` does not look like a valid integer."
            )
    else:
        # No token available; try reading a selection from the context instead
        br = BinaryReader(bv, bv.endianness)
        selected_integer_bytes = br.read(length=context.length, address=context.address)
        selected_integer_value: Optional[int] = None

        if selected_integer_bytes is not None:
            if len(selected_integer_bytes) == 4:
                try:
                    if br.endianness == Endianness.LittleEndian:
                        selected_integer_value = struct.unpack(
                            "<I", selected_integer_bytes
                        )[0]
                    elif br.endianness == Endianness.BigEndian:
                        selected_integer_value = struct.unpack(
                            ">I", selected_integer_bytes
                        )[0]
                except struct.error as err:
                    logger.log_error(
                        f"Could not interpret selection as a 32-bit integer: {err}"
                    )
            elif len(selected_integer_bytes) == 8:
                try:
                    if br.endianness == Endianness.LittleEndian:
                        selected_integer_value = struct.unpack(
                            "<Q", selected_integer_bytes
                        )[0]
                    elif br.endianness == Endianness.BigEndian:
                        selected_integer_value = struct.unpack(
                            ">Q", selected_integer_bytes
                        )[0]
                except struct.error as err:
                    logger.log_error(
                        f"Could not interpret selection as a 64-bit integer: {err}"
                    )

            if selected_integer_value is not None:
                HuntAlgorithmTask(
                    bv=bv,
                    hashdb_api_url=hashdb_api_url,
                    hash_value=selected_integer_value,
                ).start()
