"""this file deliberately contains invalid Python to exercise graceful fallback

The AST scanner must not crash on this file. It records a parse error
(visible in ``ScanResult.parse_errors``) and the regex scanner still runs
over the raw text, so the hashlib.md5 call below is still reported.
"""

import hashlib

def broken(:
    md5 = hashlib.md5(b'still detected by the regex fallback')
    return md5