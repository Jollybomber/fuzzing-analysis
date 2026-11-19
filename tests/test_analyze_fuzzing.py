"""Regression checks for analysis conclusions, without requiring AFL or parser builds."""

import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze_fuzzing.py"
spec = importlib.util.spec_from_file_location("analyzer", SCRIPT)
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)


def result(raw=b"null", status="accepted", truncated=False):
    return {"status": status, "stdout_b64": base64.b64encode(raw).decode(),
            "output_truncated": truncated}


class ComparisonTests(unittest.TestCase):
    def test_formatting_order_and_numeric_spelling_are_not_findings(self):
        left = b'{"a": 1, "b": "\\u0061", "c": [true, null]}'
        right = b'{"c":[true,null],"b":"a","a":1.0}'
        self.assertEqual(analyzer.compare(result(left), result(right)), [])

    def test_large_integers_and_decimal_precision_are_preserved(self):
        for left, right in [(b"9007199254740992", b"9007199254740993"),
                            (b"1.000000000000000005", b"1.0")]:
            self.assertEqual(analyzer.compare(result(left), result(right)), ["VALUE_DIFFERENCE"])

    def test_huge_exponent_is_valid_json_and_compared_exactly(self):
        self.assertEqual(analyzer.compare(result(b"1e1111111111111111111111"), result(b"null")),
                         ["VALUE_DIFFERENCE"])
        self.assertEqual(analyzer.compare(result(b"1e1111111111111111111111"),
                                          result(b"10e1111111111111111111110")), [])
        self.assertEqual(analyzer.compare(result(b"-0e99999999999999999999999"), result(b"0.0")), [])
        self.assertEqual(analyzer.compare(result(b"1e" + b"9" * 4001), result()), ["COMPARISON_LIMIT"])

    def test_duplicates_not_silently_collapsed(self):
        self.assertEqual(analyzer.compare(result(b'{"a":1,"a":2}'), result(b'{"a":2}')),
                         ["VALUE_DIFFERENCE"])
        self.assertEqual(analyzer.compare(result(b'{"a":1,"b":3,"a":2}'),
                                          result(b'{"b":3,"a":1,"a":2}')), [])

    def test_boolean_type_array_order_and_duplicate_order_preserved(self):
        for left, right in [(b"true", b"1"), (b"[1,2]", b"[2,1]"),
                            (b'{"a":1,"a":2}', b'{"a":2,"a":1}')]:
            self.assertEqual(analyzer.compare(result(left), result(right)), ["VALUE_DIFFERENCE"])

    def test_malformed_output_does_not_become_acceptance_disagreement(self):
        self.assertEqual(analyzer.compare(result(b'"\xff"'), result(b'"\xff"')), ["INVALID_UTF8_OUTPUT"])
        self.assertEqual(analyzer.compare(result(b'"\xff"'), result(b'"\xfe"')),
                         ["INVALID_UTF8_OUTPUT", "VALUE_DIFFERENCE"])
        # Invalid UTF-8 must not hide a value difference elsewhere in the document.
        self.assertEqual(analyzer.compare(result(b'["\xff",9.2233720368547758e+18]'),
                                          result(b'["\xff",9223372036854775807]')),
                         ["INVALID_UTF8_OUTPUT", "VALUE_DIFFERENCE"])
        self.assertEqual(analyzer.compare(result(b'"\xff"'), result(b'"\xff "')), ["INVALID_UTF8_OUTPUT", "VALUE_DIFFERENCE"])
        self.assertEqual(analyzer.compare(result(b"NaN"), result(b"NaN")), ["INVALID_JSON_OUTPUT"])
        self.assertEqual(analyzer.compare(result(b"NaN"), result()), ["INVALID_JSON_OUTPUT", "UNCOMPARABLE_OUTPUT"])
        self.assertEqual(analyzer.compare(result(b"null debug"), result(b"null debug")), ["INVALID_JSON_OUTPUT"])
        # Unparseable and different outputs must never count as agreement.
        self.assertEqual(analyzer.compare(result(b"[1] junk"), result(b"[2] junk")),
                         ["INVALID_JSON_OUTPUT", "UNCOMPARABLE_OUTPUT"])
        self.assertEqual(analyzer.compare(result(b"null debug"), result()), ["INVALID_JSON_OUTPUT", "UNCOMPARABLE_OUTPUT"])

    def test_non_rfc_number_output_is_still_compared_by_value(self):
        # json-c echoes tokens such as `1.`; equal values are not a difference...
        self.assertEqual(analyzer.compare(result(b"[1]"), result(b"[1.]")), ["INVALID_JSON_OUTPUT"])
        self.assertEqual(analyzer.compare(result(b"[-0.5]"), result(b"[-.5]")), ["INVALID_JSON_OUTPUT"])
        # ...but a real difference elsewhere in the document is still found.
        self.assertEqual(analyzer.compare(result(b'{"a":1,"a":2,"b":3}'), result(b'{"a":2,"b":3.}')),
                         ["INVALID_JSON_OUTPUT", "VALUE_DIFFERENCE"])
        # Strings that merely look like numbers are left untouched.
        self.assertEqual(analyzer.normalize_lenient_numbers('["1.",1.]'), ('["1.",1]', True))
        self.assertEqual(analyzer.normalize_lenient_numbers('["a\\\\",068e1]'), ('["a\\\\",68e1]', True))

    def test_rejection_timeout_and_truncation_are_distinct(self):
        self.assertEqual(analyzer.compare(result(status="rejected"), result()), ["ACCEPTANCE_DIFFERENCE"])
        self.assertEqual(analyzer.compare(result(status="timeout"), result()), ["ABNORMAL_EXECUTION"])
        self.assertEqual(analyzer.compare(result(truncated=True), result()), ["OUTPUT_LIMIT"])
        self.assertEqual(analyzer.compare(result(status="rejected"), result(status="rejected")), [])


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fuzz = self.root / "fuzz_out"
        self.bin = self.root / "bin"
        self.bin.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def campaign(self, name="cjson_normal_run1", worker="default", missing_hangs=False):
        folder = self.fuzz / name
        instance = folder / worker
        (instance / "queue").mkdir(parents=True)
        (instance / "hangs").mkdir()
        (instance / "crashes").mkdir()
        stats = "run_time : 1800\nexecs_done : 3600\nsaved_crashes : 0\nedges_found : 10\ntotal_edges : 100\nstability : 100%\ncommand_line : afl-fuzz -- /bin/target @@\n"
        if not missing_hangs:
            stats += "saved_hangs : 0\n"
        (instance / "fuzzer_stats").write_text(stats)
        (folder / "afl.log").write_text("Time limit was reached\n")
        (instance / "queue" / "id:000000,time:0,orig:seed.json").write_bytes(b"{}")
        (instance / "queue" / "id:000001,time:2000,src:000000").write_bytes(b"{}")
        (instance / "crashes" / "README.txt").write_text("not an input")
        return instance

    def test_dedup_keeps_provenance_and_missing_metrics_unknown(self):
        self.campaign(missing_hangs=True)
        self.campaign("cjson_normal_run2")
        data = analyzer.collect(self.fuzz, self.bin, 1800, 3)
        self.assertEqual(len(data["inputs"]), 1)
        self.assertEqual(len(data["inputs"][0]["origins"]), 4)
        first = data["runs"][0]
        self.assertEqual(first["seed_derived_queue_files"], 1)
        self.assertEqual(first["execs_per_sec"], 2)
        self.assertEqual(first["command_line"], "afl-fuzz -- /bin/target @@")
        self.assertIsNone(first["saved_hangs"])
        self.assertIsNone(data["groups"][0]["saved_hangs_sum"])
        self.assertIsNone(first["first_crashes_seconds"])
        self.assertEqual(first["crashes_files"], 0)

    def test_workers_are_not_independent_repeats(self):
        self.campaign(worker="main")
        self.campaign(worker="secondary")
        data = analyzer.collect(self.fuzz, self.bin, 1800, 3)
        self.assertEqual(data["groups"], [])
        self.assertTrue(any("Multiple workers" in w for w in data["runs"][0]["warnings"]))

    def test_label_audit_and_identical_targets(self):
        self.campaign()
        self.campaign("cjson_asan_run1")
        for name in ("cjson_afl_normal", "cjson_afl_asan"):
            (self.bin / name).write_bytes(b"example __asan_init marker")
        data = analyzer.collect(self.fuzz, self.bin, 1800, 3)
        self.assertTrue(any("IDENTICAL TARGET" in w for w in data["warnings"]))
        self.assertTrue(any("Do not calculate" in w for w in data["warnings"]))

    def test_build_manifest_provenance(self):
        self.campaign()
        target = self.bin / "cjson_afl_normal"
        target.write_bytes(b"target")
        data = analyzer.collect(self.fuzz, self.bin, 1800, 1)
        self.assertTrue(any("No run or build manifest" in w for w in data["runs"][0]["warnings"]))
        digest = analyzer.sha256(b"target")
        (self.fuzz / "build_manifest.json").write_text(json.dumps({"binaries_sha256": {"cjson_afl_normal": digest}}))
        row = analyzer.collect(self.fuzz, self.bin, 1800, 1)["runs"][0]
        self.assertTrue(row["build_manifest_sha_match"])
        self.assertFalse(any("differs from the build_manifest" in w for w in row["warnings"]))
        # Without a per-campaign run record the analyzer still warns (older campaigns).
        self.assertTrue(any("No per-campaign run_manifest.json" in w for w in row["warnings"]))
        (self.fuzz / "cjson_normal_run1" / "run_manifest.json").write_text(json.dumps({"target_sha256": digest}))
        row = analyzer.collect(self.fuzz, self.bin, 1800, 1)["runs"][0]
        self.assertFalse(any("manifest" in w for w in row["warnings"]))
        target.write_bytes(b"rebuilt target")
        row = analyzer.collect(self.fuzz, self.bin, 1800, 1)["runs"][0]
        self.assertFalse(row["build_manifest_sha_match"])
        self.assertTrue(any("differs from the build_manifest" in w for w in row["warnings"]))

    def test_existing_output_and_input_directory_are_protected(self):
        self.campaign()
        output = self.root / "analysis"
        output.mkdir()
        marker = output / "keep.txt"
        marker.write_text("keep")
        common = [sys.executable, "-B", str(SCRIPT), "--input", str(self.fuzz)]
        for path in (output, self.fuzz / "analysis"):
            process = subprocess.run(common + ["--output", str(path)], capture_output=True)
            self.assertEqual(process.returncode, 2)
        self.assertEqual(marker.read_text(), "keep")

    def test_cli_writes_report_and_does_not_change_inputs(self):
        instance = self.campaign()
        original = (instance / "fuzzer_stats").read_bytes()
        output = self.root / "analysis"
        process = subprocess.run([sys.executable, "-B", str(SCRIPT), "--input", str(self.fuzz),
                                  "--bin-dir", str(self.bin), "--output", str(output)], capture_output=True)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertEqual(json.loads((output / "summary.json").read_text())["distinct_inputs"], 1)
        self.assertIn("Replay not performed", (output / "report.md").read_text())
        self.assertEqual((instance / "fuzzer_stats").read_bytes(), original)


class ExecutionTests(unittest.TestCase):
    def test_status_signal_and_sanitizer_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            script = Path(temp) / "target.py"
            for code, expected in [("print('null')", "accepted"), ("raise SystemExit(1)", "rejected"),
                                   ("raise SystemExit(2)", "harness_error"),
                                   ("import sys; print('runtime error: bad', file=sys.stderr)", "sanitizer"),
                                   ("import os, signal; os.kill(os.getpid(), signal.SIGTERM)", "crash"),
                                   ("import time; time.sleep(1)", "timeout")]:
                script.write_text(code)
                actual = analyzer.execute(Path(sys.executable), script, 0.2)
                self.assertEqual(actual["status"], expected, actual)


if __name__ == "__main__":
    unittest.main()
