---
name: Bug report
about: Create a report to help us improve
title: ''
labels: bug
assignees: ''

---

# Description
A clear and concise description of what the bug is.

# To Reproduce
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

# Expected behavior
A clear and concise description of what you expected to happen.

# Screenshots
If applicable, add screenshots to help explain your problem.

# System Information (please complete the following information)

- Operating System: `Windows / MacOS / Linux`
- Binary Ninja Version: `VERSION`
    - You can find this by going to _Help > About..._. Clicking the version number string there will copy it to your clipboard. An example of a valid version number is `3.3.4003-dev Personal (Build ID 99e39418)`.
- Python Version: `VERSION`
    - You can find this by executing the following snippet of Python code in the built-in Python console:

        ```python
        import sys; print(sys.version_info)
        ```

        For example:

        ```python
        >>> import sys; print(sys.version_info)
        sys.version_info(major=3, minor=7, micro=16, releaselevel='final', serial=0)
        ```
- Plugin Version: `VERSION`
    - You can find this by opening the Plugin Manager (_Plugins > Manage Plugins_), searching for `HashDB`, then noting the version number listed beside the title of the plugin entry. An example of a valid version number is `v1.0.0`.
    - Alternatively, if you installed the plugin via cloning the repository to your plugin folder rather than through the Plugin Manager, you can find the plugin version in the `plugin.json` file in the `hashdb_bn` directory in your plugin folder. The plugin folder can be opened through the _Plugins > Open Plugin Folder..._ commaand.

# Additional context
Add any other context about the problem here.
