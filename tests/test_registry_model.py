import pytest

from pirate_monitor.registry.model import (
    RegistryTracker,
    canonical_key_path,
    dedupe_key_roots,
    diff_snapshots,
    format_value,
    take_snapshot,
)

from fake_registry import FakeRegistry


def actions(changes):
    return [(c.action, c.key, c.value) for c in changes]


def test_canonical_key_path_accepts_common_spellings():
    assert canonical_key_path(r"HKEY_CURRENT_USER\Software\\") == r"HKCU\Software"
    assert canonical_key_path(r"Computer\HKEY_LOCAL_MACHINE\SOFTWARE\X") == r"HKLM\SOFTWARE\X"
    assert canonical_key_path("HKLM:/SOFTWARE/X") == r"HKLM\SOFTWARE\X"
    assert canonical_key_path("hku") == "HKU"
    with pytest.raises(ValueError):
        canonical_key_path(r"HKXX\Software")


def test_dedupe_key_roots_drops_nested_keys():
    roots = dedupe_key_roots([r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", r"HKLM\SOFTWARE",
                              r"HKCU\Software", r"hklm\software\x"])
    assert roots == ["HKLM\\SOFTWARE", "HKCU\\Software"]


def test_diff_reports_values_and_collapses_deleted_trees():
    reg = FakeRegistry()
    reg.set_value(r"HKCU\Software\App", "keep", "1")
    reg.set_value(r"HKCU\Software\App", "change", "old")
    reg.set_value(r"HKCU\Software\App", "remove", "x")
    reg.set_value(r"HKCU\Software\Gone\Deep\Deeper", "v", 5, 4)
    before = take_snapshot(reg, r"HKCU\Software")

    reg.set_value(r"HKCU\Software\App", "change", "new")
    reg.delete_value(r"HKCU\Software\App", "remove")
    reg.set_value(r"HKCU\Software\App", "added", "hello")
    reg.set_value(r"HKCU\Software\New\Sub", "payload", r"C:\evil.exe")
    reg.delete_key(r"HKCU\Software\Gone")
    after = take_snapshot(reg, r"HKCU\Software")

    changes = diff_snapshots(before, after)
    acts = actions(changes)
    assert ("value_modified", r"HKCU\Software\App", "change") in acts
    assert ("value_deleted", r"HKCU\Software\App", "remove") in acts
    assert ("value_created", r"HKCU\Software\App", "added") in acts
    assert ("key_created", r"HKCU\Software\New", None) in acts
    assert ("key_created", r"HKCU\Software\New\Sub", None) in acts
    assert ("value_created", r"HKCU\Software\New\Sub", "payload") in acts
    deleted = [c for c in changes if c.action == "key_deleted"]
    assert [c.key for c in deleted] == [r"HKCU\Software\Gone"]  # one event for the whole tree
    assert deleted[0].extra["subkeys_removed"] == 2
    assert deleted[0].extra["values_removed"] == 1
    # parents are reported before their children
    assert acts.index(("key_created", r"HKCU\Software\New", None)) < acts.index(("key_created", r"HKCU\Software\New\Sub", None))


def _build_tree(reg):
    reg.set_value(r"HKCU\Software", "rootval", "r")
    for i in range(2):
        reg.set_value(rf"HKCU\Software\Small\K{i}", "v", i, 4)
    for i in range(8):
        reg.set_value(rf"HKCU\Software\Big\Child{i}\Leaf", "v", i, 4)


def test_partition_splits_big_trees_and_covers_every_key():
    reg = FakeRegistry()
    _build_tree(reg)
    tracker = RegistryTracker(reg, split_threshold=5)
    units = tracker.add_root(r"HKCU\Software")
    by_path = {u.path: u for u in units}
    assert by_path[r"HKCU\Software"].recursive is False
    assert by_path[r"HKCU\Software\Small"].recursive is True
    assert by_path[r"HKCU\Software\Big"].recursive is False
    assert by_path[r"HKCU\Software\Big\Child3"].recursive is True

    covered = [k for u in units for k in u.snapshot]
    assert len(covered) == len(set(covered))  # each key belongs to exactly one unit
    full = take_snapshot(reg, r"HKCU\Software")
    assert set(covered) == set(full)


def test_new_child_of_split_key_becomes_new_unit_with_contents_reported():
    reg = FakeRegistry()
    _build_tree(reg)
    tracker = RegistryTracker(reg, split_threshold=5)
    tracker.add_root(r"HKCU\Software")
    root = tracker.units[r"hkcu\software"]

    reg.set_value(r"HKCU\Software\Malware\Config", "c2", "http://evil.example")
    changes, added, removed = tracker.rescan(root)
    assert actions(changes) == [("key_created", r"HKCU\Software\Malware", None)]
    assert added == [r"HKCU\Software\Malware"] and removed == []

    unit = tracker.new_unit(added[0])
    ok, initial = tracker.prime(unit)
    assert ok
    assert ("key_created", r"HKCU\Software\Malware\Config", None) in actions(initial)
    assert ("value_created", r"HKCU\Software\Malware\Config", "c2") in actions(initial)
    assert ("key_created", r"HKCU\Software\Malware", None) not in actions(initial)

    reg.set_value(r"HKCU\Software\Malware\Config", "c2", "http://other.example")
    changes, _, _ = tracker.rescan(unit)
    assert actions(changes) == [("value_modified", r"HKCU\Software\Malware\Config", "c2")]
    assert changes[0].old == "http://evil.example" and changes[0].new == "http://other.example"


def test_deleted_child_unit_is_reported_once_by_parent():
    reg = FakeRegistry()
    _build_tree(reg)
    tracker = RegistryTracker(reg, split_threshold=5)
    tracker.add_root(r"HKCU\Software")
    small = tracker.units[r"hkcu\software\small"]
    root = tracker.units[r"hkcu\software"]

    reg.delete_key(r"HKCU\Software\Small")
    # The child's own notification usually arrives first: it just marks itself dead.
    assert tracker.rescan(small) == ([], [], [])
    assert small.dead
    changes, added, removed = tracker.rescan(root)
    assert actions(changes) == [("key_deleted", r"HKCU\Software\Small", None)]
    assert changes[0].extra["subkeys_removed"] == 2
    assert removed == [small] and added == []


def test_dead_unit_recreated_between_scans_is_restarted():
    reg = FakeRegistry()
    _build_tree(reg)
    tracker = RegistryTracker(reg, split_threshold=5)
    tracker.add_root(r"HKCU\Software")
    small = tracker.units[r"hkcu\software\small"]
    small.dead = True
    changes, added, removed = tracker.rescan(tracker.units[r"hkcu\software"])
    assert [c.action for c in changes] == ["key_deleted", "key_created"]
    assert added == [r"HKCU\Software\Small"] and removed == [small]


def test_removing_a_split_subtree_removes_all_its_units():
    reg = FakeRegistry()
    _build_tree(reg)
    tracker = RegistryTracker(reg, split_threshold=5)
    tracker.add_root(r"HKCU\Software")
    reg.delete_key(r"HKCU\Software\Big")
    changes, _, removed = tracker.rescan(tracker.units[r"hkcu\software"])
    assert actions(changes) == [("key_deleted", r"HKCU\Software\Big", None)]
    assert changes[0].extra["subkeys_removed"] == 16
    assert len(removed) == 9  # Big + 8 children
    for unit in removed:
        tracker.drop(unit)
    assert not any(k.startswith(r"hkcu\software\big") for k in tracker.units)


def test_top_level_root_deletion_is_reported_by_the_root_unit():
    reg = FakeRegistry()
    reg.set_value(r"HKCU\Software\Watched\X", "v", 1, 4)
    tracker = RegistryTracker(reg)
    (unit,) = tracker.add_root(r"HKCU\Software\Watched")
    reg.delete_key(r"HKCU\Software\Watched")
    changes, added, removed = tracker.rescan(unit)
    assert actions(changes) == [("key_deleted", r"HKCU\Software\Watched", None)]
    assert removed == [unit]


def test_unchanged_old_keys_reuse_cached_values():
    reg = FakeRegistry()
    reg.set_value(r"HKCU\Software\Old", "v", "1")
    reg.age(r"HKCU\Software\Old", 3600)
    first = take_snapshot(reg, r"HKCU\Software")
    # Mutate the data behind the registry's back without touching last_write: the cached
    # values are reused, proving the optimisation kicks in for untouched keys.
    reg.open(r"HKCU\Software\Old").values["v"] = ("v", "2", 1)
    second = take_snapshot(reg, r"HKCU\Software", previous=first)
    assert second[r"hkcu\software\old"].values is first[r"hkcu\software\old"].values
    # A real write updates last_write and is always picked up.
    reg.set_value(r"HKCU\Software\Old", "v", "3")
    third = take_snapshot(reg, r"HKCU\Software", previous=second)
    assert third[r"hkcu\software\old"].values["v"][2] == "3"


def test_skipped_subtrees_are_not_walked_or_watched():
    reg = FakeRegistry()
    _build_tree(reg)
    reg.set_value(r"HKCU\Software\Huge\X", "v", 1, 4)
    tracker = RegistryTracker(reg, split_threshold=5, skip=[r"HKCU\Software\Huge"])
    units = tracker.add_root(r"HKCU\Software")
    assert not any(k.startswith(r"hkcu\software\huge") for u in units for k in u.snapshot)
    assert tracker.new_unit(r"HKCU\Software\Huge") is None
    changes, added, _ = tracker.rescan(tracker.units[r"hkcu\software"])
    assert changes == [] and added == []  # an existing skipped child is not "new"


def test_large_binary_values_are_fingerprinted():
    reg = FakeRegistry()
    reg.set_value(r"HKCU\Software\Bin", "blob", b"\x00" * 1000, 3)
    snap = take_snapshot(reg, r"HKCU\Software\Bin")
    stored = snap[r"hkcu\software\bin"].values["blob"][2]
    assert stored[0] == "<binary>" and stored[1] == 1000
    assert "1,000 bytes" in format_value(3, stored)
    assert format_value(4, 1) == "1 (0x1)"
    assert format_value(7, ["a", "b"]) == "a | b"
    assert format_value(3, b"\x01\x02") == "hex[2]: 01 02"
