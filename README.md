# Binary Ninja HashDB Plugin

[HashDB](https://github.com/OALabs/hashdb) is a community-sourced library of hashing algorithms used in malware. This plugin queries the [OALabs HashDB Lookup Service](https://hashdb.openanalysis.net/) for hash values which appear in the currently analyzed file, fetches a list of strings which match those hashes, and collects the string values into a type definition (e.g. an enum). The defined type can then be applied to the binary for further analysis.

![](images/hashlookup-screenshot-border.png)

![](images/hashlookup-result-screenshot-border.png)

## Installation

This plugin can be installed via either:

1) (Available soon) Binary Ninja's built-in plugin manager (_Plugins > Manage Plugins_).

2) Cloning this repository into your user plugins folder.
    - The [location of the user plugins folder will vary depending on the platform Binary Ninja is installed on](https://docs.binary.ninja/guide/index.html#user-folder). The easiest way to find the location of the folder is via the _Plugins > Open Plugin Folder..._ command.
    - If you are performing an installation via this method, you must also install this plugin's Python dependencies manually. This can be done by either:
        - Running the _Install python3 module..._ command (via the Command Palette), and pasting the contents of [`requirements.txt`](requirements.txt) in this repository into the dialog window.
        - Running `pip install -r requirements.txt` in the Python environment used by Binary Ninja.

## License

This plugin is released under a 3-Clause BSD license.

This plugin is a derivative work of the [IDA Plugin](https://github.com/OALabs/hashdb-ida/) from [OALabs](https://oalabs.openanalysis.net/) for connecting to their [HashDB service](https://hashdb.openanalysis.net/), and is forked from Vector 35's initial implementation at [psifertex/hashdb-bn](https://github.com/psifertex/hashdb-bn).