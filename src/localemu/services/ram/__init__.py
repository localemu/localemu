"""RAM (Resource Access Manager) service for LocalEmu.

Control plane delegates entirely to moto. On top we add:
  - A patch filling moto's missing AssociateResourceShare/
    DisassociateResourceShare operations (``_moto_patches.py``).
  - A helper (``helpers.py``) that lets other services' Describe/List
    handlers (currently just EC2's DescribeSubnets) make a RAM-shared
    resource visible to the account(s) it was shared with - RAM itself
    never enforces or surfaces this; each consuming service must opt in.

Moto patches are applied at import time so the first provider construction
inherits them.
"""

from localemu.services.ram import _moto_patches as _moto_patches

_moto_patches.apply()
