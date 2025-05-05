import sys
from maturin import *  # Import everything from maturin

MAX_MINOR_VERSION = 13  # Python 3.13 is latest supported version
MAJOR = sys.version_info.major
MINOR = min(sys.version_info.minor, MAX_MINOR_VERSION)

current_args = os.environ.get("MATURIN_PEP517_ARGS", "")
if "--features" not in current_args:
    # This is a thin wrapper around maturin to set the ABI3 feature flag
    # for the current Python version so we use the limited ABI3 for the
    # current Python version as maturin does not have a way to do
    # this automatically.
    features_arg = f" --features=pyo3/abi3-py{MAJOR}{MINOR}"
    os.environ["MATURIN_PEP517_ARGS"] = current_args + features_arg
