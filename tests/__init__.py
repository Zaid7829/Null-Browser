import os


def load_tests(loader, standard_tests, pattern):
    """Discovers tests inside non-identifier directories like tests/control-panel."""
    cp_dir = os.path.join(os.path.dirname(__file__), "control-panel")
    if os.path.isdir(cp_dir):
        pat = pattern if pattern else "test_*.py"
        cp_suite = loader.discover(start_dir=cp_dir, pattern=pat, top_level_dir=cp_dir)
        standard_tests.addTests(cp_suite)
    return standard_tests
