import os

import pytest

from unitech_v3.pathguard import PathDenied, safe_join, validate_under_roots


def test_inside_root_ok(tmp_path):
    (tmp_path / "p").mkdir()
    assert validate_under_roots(str(tmp_path / "p"), [tmp_path]) == (tmp_path / "p").resolve()


@pytest.mark.parametrize("raw", ["../", "/etc", "..\\..\\Windows", "", "a\x00b"])
def test_outside_or_invalid_denied(tmp_path, raw):
    with pytest.raises(PathDenied):
        validate_under_roots(str(tmp_path / raw) if raw not in ("", "a\x00b", "/etc") else raw, [tmp_path])


def test_dotdot_escape_denied(tmp_path):
    root = tmp_path / "root"; root.mkdir(); (tmp_path / "other").mkdir()
    with pytest.raises(PathDenied):
        validate_under_roots(str(root / ".." / "other"), [root])


def test_symlink_escape_denied(tmp_path):
    root = tmp_path / "root"; root.mkdir(); out = tmp_path / "out"; out.mkdir()
    os.symlink(out, root / "l")
    with pytest.raises(PathDenied):
        validate_under_roots(str(root / "l"), [root])


def test_symlink_inside_root_still_denied(tmp_path):
    root = tmp_path / "root"; (root / "a").mkdir(parents=True); os.symlink(root / "a", root / "alias")
    with pytest.raises(PathDenied):
        validate_under_roots(str(root / "alias"), [root])


def test_prefix_sibling_not_confused(tmp_path):
    root = tmp_path / "proj"; root.mkdir(); sib = tmp_path / "proj-evil"; sib.mkdir()
    with pytest.raises(PathDenied):
        validate_under_roots(str(sib), [root])


@pytest.mark.parametrize("rel", ["../x", "/abs", "C:\\x", "a/../../x", ""])
def test_safe_join_rejects(tmp_path, rel):
    with pytest.raises(PathDenied):
        safe_join(tmp_path, rel)


def test_safe_join_ok(tmp_path):
    (tmp_path / "d").mkdir(); (tmp_path / "d" / "f").write_text("x")
    assert safe_join(tmp_path, "d/f").name == "f"
