# Third-party notices

This document records third-party material that is distributed with, or is
required by, `wazuhregex`. It is not a substitute for the license text supplied
by each upstream project.

## Wazuh test cases

`tests/test_wazuhregex.py` contains regex patterns and sample inputs adapted
from the Wazuh C unit tests. Wazuh is distributed under the GNU General Public
License, version 2. The adapted test material is distributed as part of this
GPL-2.0-only project under the terms in [`LICENSE`](LICENSE).

- Upstream project: <https://github.com/wazuh/wazuh>
- Upstream license: <https://github.com/wazuh/wazuh/blob/master/LICENSE>

No Wazuh binaries or library source files are included. Wazuh and related
names are the property of their respective owners. This project is independent
and is not endorsed by Wazuh.

## Runtime dependencies

Runtime dependencies are installed separately by the Python package installer;
their source is not vendored in this repository.

| Dependency | Declared license | Project |
| --- | --- | --- |
| `pcre2` | BSD 3-Clause | <https://github.com/grtetrault/pcre2.py> |
| `rich` | MIT | <https://github.com/Textualize/rich> |

Development and build tools are listed in `pyproject.toml` and are likewise not
redistributed as part of this source tree.
