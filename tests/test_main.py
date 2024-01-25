from main import PynTester


def test_initial_command_history_is_empty():
    pyntester = PynTester()
    assert pyntester.command_history == []


def test_show_help():
    pyntester = PynTester()
    # This is a simple test to check if show_help method runs without errors
    try:
        pyntester.show_help()
    except Exception as e:
        assert False, f"show_help raised exception {e}"
