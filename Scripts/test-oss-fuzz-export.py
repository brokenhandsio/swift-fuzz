#!/usr/bin/env python3
"""Exercise the generated build helper; pass its path as the first argument."""
import configparser
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

helper = Path(sys.argv.pop(1))
spec = importlib.util.spec_from_file_location("swift_fuzz_export", helper)
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.package = self.root / "package with spaces"
        self.output = self.root / "out"
        self.package.mkdir()
        self.output.mkdir()

    def input(self, path, contents):
        file = self.package / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(contents)
        return file

    def archive_contents(self):
        with zipfile.ZipFile(self.output / "Decode_seed_corpus.zip") as archive:
            self.assertTrue(all(len(name) == 64 for name in archive.namelist()))
            return {archive.read(name) for name in archive.namelist()}

    def test_seeds_only_with_nested_duplicate_names_empty_inputs_and_placeholders(self):
        self.input("Seeds/Decode/a/sample", b"first")
        self.input("Seeds/Decode/b/sample", b"second")
        self.input("Seeds/Decode/duplicate", b"first")
        self.input("Seeds/Decode/empty", b"")
        self.input("Seeds/Decode/.gitkeep", b"placeholder")
        self.input("Corpus/Decode/discovery", b"not committed")
        outside = self.input("unrelated", b"outside")
        (self.package / "Seeds/Decode/link").symlink_to(outside)
        exporter.package_inputs(self.package, "Decode", self.output, False)
        self.assertEqual(self.archive_contents(), {b"first", b"second", b""})

    def test_corpus_is_explicit_and_archive_is_replaced(self):
        seed = self.input("Seeds/Decode/sample", b"seed")
        self.input("Corpus/Decode/sample", b"discovery")
        exporter.package_inputs(self.package, "Decode", self.output, True)
        self.assertEqual(self.archive_contents(), {b"seed", b"discovery"})
        seed.write_bytes(b"new seed")
        exporter.package_inputs(self.package, "Decode", self.output, False)
        self.assertEqual(self.archive_contents(), {b"new seed"})

    def test_missing_inputs_are_valid(self):
        exporter.package_inputs(self.package, "Decode", self.output, False)
        self.assertFalse((self.output / "Decode_seed_corpus.zip").exists())

    def test_symlinked_seed_root_is_skipped(self):
        self.input("Elsewhere/Decode/sample", b"outside seed directory")
        (self.package / "Seeds").symlink_to(self.package / "Elsewhere", target_is_directory=True)
        exporter.package_inputs(self.package, "Decode", self.output, False)
        self.assertFalse((self.output / "Decode_seed_corpus.zip").exists())

    def test_custom_options_preserve_sanitizer_settings_and_override_defaults(self):
        self.input("Options/Decode.options", b"[libfuzzer]\nuse_value_profile=0\nmax_len=123\n[asan]\nstrict_string_checks=1\n")
        self.input("Dictionaries/Decode.dict", b'"token"\n')
        exporter.package_options(self.package, "Decode", self.output)
        options = configparser.ConfigParser()
        options.read(self.output / "Decode.options")
        self.assertEqual(options["libfuzzer"]["use_value_profile"], "0")
        self.assertEqual(options["libfuzzer"]["detect_leaks"], "0")
        self.assertEqual(options["libfuzzer"]["dict"], "Decode.dict")
        self.assertEqual(options["asan"]["strict_string_checks"], "1")
        self.assertEqual((self.output / "Decode.dict").read_bytes(), b'"token"\n')

    def test_invalid_or_colliding_names_are_rejected(self):
        for names in [["../escape"], [" Leading"], ["llvm-symbolizer"], ["A", "a"], ["A", "A"]]:
            with self.subTest(names=names), self.assertRaises(ValueError):
                exporter.checked_names(names)
        self.assertEqual(exporter.checked_names(["Decode", "Other-Target"]), ["Decode", "Other-Target"])

    def test_target_exclusions_are_checked_and_case_insensitive(self):
        targets = [
            {"product": "Combined", "target": "Decode"},
            {"product": "Combined", "target": "KnownCrash"},
        ]
        self.assertEqual(exporter.select_targets(targets, ["knowncrash"]), targets[:1])
        with self.assertRaisesRegex(ValueError, "was not discovered"):
            exporter.select_targets(targets, ["Typo"])
        with self.assertRaisesRegex(ValueError, "All discovered"):
            exporter.select_targets(targets, ["Decode", "KnownCrash"])

    def test_targets_from_one_product_share_one_executable_inode(self):
        binaries = self.root / "bin"
        destination = self.root / "stage"
        binaries.mkdir()
        destination.mkdir()
        (binaries / "Combined").write_bytes(b"\x7fELFcombined")
        (binaries / "Other").write_bytes(b"\x7fELFother")
        targets = [
            {"product": "Combined", "target": "Decode"},
            {"product": "Combined", "target": "AsyncDecode"},
            {"product": "Other", "target": "Single"},
        ]
        exporter.stage_executables(targets, binaries, destination)
        self.assertEqual((destination / "Decode").stat().st_ino, (destination / "AsyncDecode").stat().st_ino)
        self.assertNotEqual((destination / "Decode").stat().st_ino, (destination / "Single").stat().st_ino)
        self.assertTrue((destination / "Decode").stat().st_mode & 0o111)


unittest.main()
