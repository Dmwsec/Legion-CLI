from core.tools import TOOL_REGISTRY, list_tools


def test_tool_count_label_is_dynamic(capsys):
    list_tools()
    out = capsys.readouterr().out
    assert f"Legion Tool Registry - {len(TOOL_REGISTRY)} Tools" in out
