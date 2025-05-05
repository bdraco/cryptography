import sys
from maturin import *  # Import everything from maturin

MAX_MINOR_VERSION = 13  # Python 3.13 is latest supported version
MAJOR = sys.version_info.major
MINOR = min(sys.version_info.minor, MAX_MINOR_VERSION)

os.environ["MATURIN_PEP517_ARGS"] = (
    os.environ.get("MATURIN_PEP517_ARGS", "")
    + f" --features=pyo3/abi3-py{MAJOR}{MINOR}"
)
