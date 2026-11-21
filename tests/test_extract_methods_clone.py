import logging
import shutil
import json
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.extract_methods_single_csv import (  # noqa: E402
    RepositoryIndexer,
    SingleCsvMethodExtractor,
    kotlin_facade_name,
    revision_pin,
)


class KotlinFacadeNameTests(unittest.TestCase):
    """Herald's ClientCerts.android.kt (2026-11-05) compiles to ClientCerts_androidKt."""

    def test_the_facade_is_named_as_the_compiler_names_it(self):
        self.assertEqual(kotlin_facade_name("ClientCerts.android", ""), "ClientCerts_androidKt")
        self.assertEqual(kotlin_facade_name("utils", ""), "UtilsKt")
        self.assertEqual(kotlin_facade_name("Crypto-Helpers", ""), "Crypto_HelpersKt")
        self.assertEqual(kotlin_facade_name(
            "Hashing", '@file:JvmName("HashUtil")\npackage a.b\n'), "HashUtil")

    def test_the_index_maps_the_facade_to_its_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "ClientCerts.android.kt"
            source.write_text("package dev.core.gateway\nfun tlsContext() = 1\n", encoding="utf-8")
            indexer = RepositoryIndexer(Path(directory), logging.getLogger("test"))
            self.assertIn("dev.core.gateway.ClientCerts_androidKt",
                          indexer._extract_classes_from_file(source))


class CloneRepositoriesAutocrlfTests(unittest.TestCase):
    """Regression test for a real broken run.

    outputs/cloned_projects/com.ivanovsky.passnotes_11700.apk was cloned
    while the invoking machine's global git config had core.autocrlf=true,
    so every text file came out CRLF-converted on disk while HEAD still
    recorded LF. Every later pipeline stage that assumes a fresh clone is
    clean -- worktree_manager's "Base clone has uncommitted changes" guard
    in particular -- then fails on that repository for every single
    finding. Pinning core.autocrlf=false on the clone call itself makes the
    checkout deterministic no matter what git config is ambient on the
    machine that runs the pipeline.
    """

    def test_clone_pins_autocrlf_false_regardless_of_ambient_git_config(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = SingleCsvMethodExtractor(
                output_dir=str(Path(directory) / "out"),
                methods_output_dir=str(Path(directory) / "methods"),
            )
            extractor.apk_urls = {"some.apk": "https://example.invalid/some/repo.git"}
            extractor.clone_retries = 1

            with patch("cognalys.extraction.extract_methods_single_csv.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 1
                mock_run.return_value.stderr = "simulated failure"
                mock_run.return_value.stdout = ""
                extractor.clone_repositories()

            self.assertEqual(mock_run.call_count, 1)
            argv = mock_run.call_args[0][0]
            self.assertIn("-c", argv)
            autocrlf_index = argv.index("-c") + 1
            self.assertEqual(argv[autocrlf_index], "core.autocrlf=false")
            self.assertIn("clone", argv)


class ByteOrderMarkCsvTests(unittest.TestCase):
    """Regression test for a real broken run.

    data/processed/er5.csv was exported with a UTF-8 BOM. Read as plain
    utf-8, DictReader names the first column "\ufeffapk", so row.get("apk")
    returns "" for every row, apk_name silently falls back to the last path
    segment of apk_url, and the --project filter matches nothing. The
    SQLInjectionSpec run against owncloud/android logged "0 linhas validas
    carregadas" and never cloned a repository, with no error anywhere to say
    the header had not been read.
    """

    HEADER = "apk,repo_url,repo,class,method,message,unique_msg,spec\n"
    ROW = (
        "owncloud-android-2.21.1.apk,https://github.com/owncloud/android,"
        "owncloud/android,com.owncloud.android.providers.FileContentProvider,"
        "delete,concatenated predicate,unique,SQLInjectionSpec\n"
    )

    def _rows_for(self, encoding: str) -> list:
        with tempfile.TemporaryDirectory() as directory:
            csv_file = Path(directory) / "findings.csv"
            csv_file.write_text(self.HEADER + self.ROW, encoding=encoding)
            extractor = SingleCsvMethodExtractor(
                output_dir=str(Path(directory) / "out"),
                methods_output_dir=str(Path(directory) / "methods"),
                project="owncloud-android-2.21.1.apk",
            )
            extractor.read_csv(str(csv_file))
            return list(extractor.rows)

    def test_project_filter_survives_a_byte_order_mark(self):
        for encoding in ("utf-8", "utf-8-sig"):
            with self.subTest(encoding=encoding):
                rows = self._rows_for(encoding)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["apk"], "owncloud-android-2.21.1.apk")
                self.assertEqual(rows[0]["spec"], "SQLInjectionSpec")
                self.assertEqual(
                    rows[0]["repo_url"], "https://github.com/owncloud/android"
                )


class MissingMethodDependencyFindingTests(unittest.TestCase):
    """A dependency finding whose method is gone is recorded, not failed.

    NewPipe's row names NewPipeSettings.init, which does not exist (the
    method is initSettings), and the file already imports
    androidx.preference.PreferenceManager. The row failed extraction, and as
    the only row it aborted the run before the message was ever checked.
    """

    HEADER = "apk,repo_url,repo,class,method,message,unique_msg,spec\n"
    SOURCE = (
        "package org.schabi.newpipe.settings;\n\n"
        "import androidx.preference.PreferenceManager;\n\n"
        "public final class NewPipeSettings {\n"
        "    public static void initSettings(final Context context) {\n"
        "        PreferenceManager.setDefaultValues(context, 1, true);\n"
        "    }\n"
        "}\n"
    )

    def _extract(self, directory: str, message: str) -> SingleCsvMethodExtractor:
        root = Path(directory)
        repo = root / "clones" / "org.schabi.newpipe_0.25.0.apk"
        source = repo / "app/src/main/java/org/schabi/newpipe/settings/NewPipeSettings.java"
        source.parent.mkdir(parents=True)
        source.write_text(self.SOURCE, encoding="utf-8")
        (repo / "app" / "build.gradle").write_text("android {}\n", encoding="utf-8")
        for argv in (
            ["init", "-q"],
            ["config", "user.email", "test@example.invalid"],
            ["config", "user.name", "Test"],
            ["add", "-A"],
            ["commit", "-q", "-m", "initial"],
        ):
            subprocess.run(["git", "-C", str(repo), *argv], check=True,
                           capture_output=True, text=True)
        csv_file = root / "findings.csv"
        csv_file.write_text(
            self.HEADER
            + "org.schabi.newpipe_0.25.0.apk,https://github.com/TeamNewPipe/NewPipe,"
            + "TeamNewPipe/NewPipe,org.schabi.newpipe.settings.NewPipeSettings,init,"
            + f'"{message}",unique,DeprecatedApiSpec\n',
            encoding="utf-8",
        )
        extractor = SingleCsvMethodExtractor(
            output_dir=str(root / "clones"),
            methods_output_dir=str(root / "methods"),
            project="org.schabi.newpipe_0.25.0.apk",
        )
        extractor.read_csv(str(csv_file))
        extractor.cloned_repos = {"org.schabi.newpipe_0.25.0.apk": repo}
        with unittest.mock.patch.dict("os.environ", {"TCC_SKIP_APK_EVIDENCE": "1"}):
            extractor.extract_methods()
        return extractor

    def test_the_finding_is_recorded_with_its_grounding(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = self._extract(
                directory,
                "android.preference.PreferenceManager is deprecated. "
                "Use androidx.preference.PreferenceManager.",
            )
            [record_path] = list((Path(directory) / "methods").rglob("*.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(extractor.extraction_counts, (1, 0))
        self.assertEqual(
            record["extraction_metadata"]["extraction_status"], "method_not_found",
        )
        self.assertEqual(record["dependency_finding"]["status"], "not_found")
        self.assertTrue(record["class_info"]["source_file_path"].endswith(
            "NewPipeSettings.java",
        ))

    def test_a_finding_that_names_no_dependency_is_recorded_too(self):
        # It used to fail here and leave no record, so no report of the run
        # ever mentioned it. The analysis stage now closes it with its reason.
        with tempfile.TemporaryDirectory() as directory:
            extractor = self._extract(
                directory, "expecting one of PKIX,SunX509 but found .",
            )
            [record_path] = list((Path(directory) / "methods").rglob("*.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(extractor.extraction_counts, (1, 0))
        self.assertEqual(
            record["extraction_metadata"]["extraction_status"], "method_not_found",
        )
        self.assertFalse(record["dependency_finding"])


class UnextractedRowTests(unittest.TestCase):
    """Every input row leaves a record the analysis stage can account for."""

    def test_a_repository_that_did_not_clone_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_file = root / "findings.csv"
            csv_file.write_text(
                "apk,repo_url,repo,class,method,message,unique_msg,spec\n"
                "gone.apk,https://example.invalid/gone,gone/gone,"
                "com.gone.Widget,draw,\"NullPointerException: x\","
                "unique-gone,NullPointerSpec\n",
                encoding="utf-8",
            )
            extractor = SingleCsvMethodExtractor(
                output_dir=str(root / "clones"),
                methods_output_dir=str(root / "methods"),
            )
            extractor.read_csv(str(csv_file))
            extractor.cloned_repos = {"other.apk": root}
            extractor.extract_methods()
            [record_path] = list((root / "methods").rglob("*.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
        # Still a failure of the step: a clone that did not happen is not a
        # fact about the finding.
        self.assertEqual(extractor.extraction_counts, (0, 1))
        self.assertEqual(
            record["extraction_metadata"]["extraction_status"],
            "repository_not_cloned",
        )
        self.assertEqual(record["error"]["unique_error_id"], "unique-gone")
        self.assertEqual(record["source_code"]["method_body"], "")


class ResolveClassTests(unittest.TestCase):
    """A namesake is accepted only inside the reported class's organisation."""

    def _indexer(self, directory: str, names: list) -> RepositoryIndexer:
        indexer = RepositoryIndexer(Path(directory), logging.getLogger("test"))
        indexer.class_index = {
            name: Path(directory) / (name.replace(".", "/") + ".java")
            for name in names
        }
        return indexer

    def test_an_exact_name_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            indexer = self._indexer(directory, ["com.amaze.utils.FileUtils"])
            path, resolution = indexer.resolve_class("com.amaze.utils.FileUtils")
        self.assertIsNotNone(path)
        self.assertEqual(resolution["method"], "exact")

    def test_a_moved_class_in_the_same_organisation_is_found_and_labelled(self):
        with tempfile.TemporaryDirectory() as directory:
            indexer = self._indexer(
                directory, ["com.amaze.filemanager.filesystem.files.FileUtils"])
            path, resolution = indexer.resolve_class(
                "com.amaze.filemanager.utils.FileUtils")
        self.assertIsNotNone(path)
        self.assertEqual(resolution["method"], "simple_name_fallback")
        self.assertEqual(
            resolution["resolved_class"],
            "com.amaze.filemanager.filesystem.files.FileUtils",
        )

    def test_a_namesake_from_another_organisation_is_not_the_class(self):
        with tempfile.TemporaryDirectory() as directory:
            indexer = self._indexer(directory, ["org.other.io.FileUtils"])
            path, resolution = indexer.resolve_class(
                "com.amaze.filemanager.utils.FileUtils")
        self.assertIsNone(path)
        self.assertEqual(resolution["method"], "not_found")

    def test_the_closest_package_wins_and_a_tie_is_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            indexer = self._indexer(directory, [
                "com.amaze.filemanager.filesystem.FileUtils",
                "com.amaze.other.FileUtils",
            ])
            _, resolution = indexer.resolve_class(
                "com.amaze.filemanager.utils.FileUtils")
            self.assertEqual(
                resolution["resolved_class"],
                "com.amaze.filemanager.filesystem.FileUtils",
            )
            tied = self._indexer(directory, [
                "com.amaze.a.FileUtils", "com.amaze.b.FileUtils",
            ])
            path, resolution = tied.resolve_class("com.amaze.c.FileUtils")
        self.assertIsNone(path)
        self.assertEqual(resolution["method"], "ambiguous_simple_name")


class RepositoryIndexCacheTests(unittest.TestCase):
    """The class index depends only on the checked-out commit.

    Rebuilding it walked every .java and .kt file and re-ran the class
    regexes, 14-34s per run in the runs of 2026-09-07, repeated in full even
    when the clone was reused verbatim from the previous run.
    """

    def _repository(self, directory: str) -> Path:
        repo = Path(directory) / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "Example.java").write_text(
            "package com.example;\npublic class Example {}\n", encoding="utf-8"
        )
        for argv in (
            ["init", "-q"],
            ["config", "user.email", "test@example.invalid"],
            ["config", "user.name", "Test"],
            ["add", "-A"],
            ["commit", "-q", "-m", "initial"],
        ):
            subprocess.run(
                ["git", "-C", str(repo), *argv], check=True,
                capture_output=True, text=True,
            )
        return repo

    def test_second_build_reuses_the_cached_index_for_the_same_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            logger = logging.getLogger("test-index-cache")

            first = RepositoryIndexer(repo, logger)
            first.build_index()
            self.assertIn("com.example.Example", first.class_index)
            self.assertTrue((repo / ".git" / "pipeline_class_index.json").is_file())

            second = RepositoryIndexer(repo, logger)
            with patch.object(
                RepositoryIndexer, "_extract_classes_from_file"
            ) as never_called:
                second.build_index()
            never_called.assert_not_called()
            self.assertEqual(second.class_index, first.class_index)
            # Sources are still readable: the walk is skipped, not the files.
            self.assertIn(
                "class Example",
                second.get_file_content(second.class_index["com.example.Example"]),
            )

    def test_a_dirty_working_tree_rebuilds_instead_of_trusting_the_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            logger = logging.getLogger("test-index-cache")
            RepositoryIndexer(repo, logger).build_index()

            (repo / "src" / "Added.java").write_text(
                "package com.example;\npublic class Added {}\n", encoding="utf-8"
            )
            rebuilt = RepositoryIndexer(repo, logger)
            rebuilt.build_index()
            self.assertIn("com.example.Added", rebuilt.class_index)

    def test_the_cache_never_lands_in_the_working_tree(self):
        # A clone with uncommitted changes is treated as unusable by later
        # stages, so the cache lives inside .git where git ignores it.
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            RepositoryIndexer(repo, logging.getLogger("test-index-cache")).build_index()

            status = subprocess.run(
                ["git", "-C", str(repo), "status", "--porcelain"],
                capture_output=True, text=True, check=True,
            )
            self.assertEqual(status.stdout.strip(), "")


class RevisionPinTests(unittest.TestCase):
    """CVE-2021-21385 names tag v1.0.0 of openMF/mifos-mobile, whose default
    branch has since been rewritten as a Kotlin Multiplatform project without
    the reported class or its package. er7.csv said so in priority_reason and
    nothing read it, so run_20260909_100446 analysed the wrong revision."""

    def test_a_commit_is_read_out_of_free_text(self):
        row = {
            "priority_reason": (
                "EXTERNAL_CONFIRMED; HISTORICAL_VERSION; checkout=v1.0.0; "
                "commit=476b7506671a32513318e12e82467b6b660c6c69; "
                "source=https://github.com/openMF/mifos-mobile/blob/476b7506"
            ),
        }
        self.assertEqual(
            revision_pin(row), "476b7506671a32513318e12e82467b6b660c6c69",
        )

    def test_a_commit_outranks_a_tag(self):
        row = {"checkout": "v1.0.0", "commit": "abc1234"}
        self.assertEqual(revision_pin(row), "abc1234")

    def test_a_tag_is_used_when_no_commit_is_named(self):
        row = {"priority_reason": "HISTORICAL_VERSION; checkout=v1.0.0"}
        self.assertEqual(revision_pin(row), "v1.0.0")

    def test_a_row_naming_no_revision_pins_nothing(self):
        self.assertEqual(revision_pin({"priority_reason": "A"}), "")
        self.assertEqual(revision_pin({}), "")

    def test_an_unpinned_repository_is_left_on_its_default_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = SingleCsvMethodExtractor(
                output_dir=str(Path(directory) / "out"),
                methods_output_dir=str(Path(directory) / "methods"),
            )
            with patch("cognalys.extraction.extract_methods_single_csv.subprocess.run") as mock_run:
                self.assertTrue(
                    extractor._apply_revision_pin(Path(directory), "some.apk")
                )
                mock_run.assert_not_called()

    def test_a_pinned_repository_is_fetched_and_detached_at_the_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = SingleCsvMethodExtractor(
                output_dir=str(Path(directory) / "out"),
                methods_output_dir=str(Path(directory) / "methods"),
            )
            extractor.apk_revisions = {"some.apk": "476b7506"}
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                result = unittest.mock.Mock()
                result.returncode = 1 if command[3] == "rev-parse" else 0
                result.stdout = ""
                result.stderr = ""
                return result

            with patch(
                "cognalys.extraction.extract_methods_single_csv.subprocess.run", side_effect=fake_run
            ):
                self.assertTrue(
                    extractor._apply_revision_pin(Path(directory), "some.apk")
                )

            self.assertIn(
                ["git", "-C", directory, "fetch", "--depth", "1", "origin",
                 "476b7506"],
                calls,
            )
            self.assertIn(
                ["git", "-C", directory, "checkout", "--detach", "FETCH_HEAD"],
                calls,
            )

    def test_a_clone_already_at_the_revision_is_not_refetched(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = SingleCsvMethodExtractor(
                output_dir=str(Path(directory) / "out"),
                methods_output_dir=str(Path(directory) / "methods"),
            )
            extractor.apk_revisions = {"some.apk": "476b7506"}
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                result = unittest.mock.Mock()
                result.returncode = 0
                result.stdout = "476b7506671a32513318e12e82467b6b660c6c69"
                result.stderr = ""
                return result

            with patch(
                "cognalys.extraction.extract_methods_single_csv.subprocess.run", side_effect=fake_run
            ):
                self.assertTrue(
                    extractor._apply_revision_pin(Path(directory), "some.apk")
                )

            self.assertEqual(len(calls), 1)
            self.assertIn("rev-parse", calls[0])

    def test_an_unfetchable_revision_is_reported_rather_than_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = SingleCsvMethodExtractor(
                output_dir=str(Path(directory) / "out"),
                methods_output_dir=str(Path(directory) / "methods"),
            )
            extractor.apk_revisions = {"some.apk": "deadbee"}

            def fake_run(command, **kwargs):
                result = unittest.mock.Mock()
                result.returncode = 1
                result.stdout = ""
                result.stderr = "no such object"
                return result

            with patch(
                "cognalys.extraction.extract_methods_single_csv.subprocess.run", side_effect=fake_run
            ):
                self.assertFalse(
                    extractor._apply_revision_pin(Path(directory), "some.apk")
                )


class UnavailablePinTests(unittest.TestCase):
    """A pinned commit that cannot be checked out leaves its findings unanalysed (A4).

    _apply_revision_pin returned False and every caller went on: extraction
    read the default branch, other code than the one the finding was reported
    against, and the record named the intended commit as if it were the one
    read.
    """

    def _git(self, *arguments, cwd):
        return subprocess.run(["git", *arguments], cwd=cwd, check=True,
                              capture_output=True, text=True).stdout.strip()

    def _origin(self, root: Path) -> tuple:
        origin = root / "origin"
        origin.mkdir()
        self._git("init", "-q", "-b", "main", cwd=origin)
        self._git("config", "user.email", "t@example.com", cwd=origin)
        self._git("config", "user.name", "T", cwd=origin)
        commits = []
        for text in ("one", "two"):
            (origin / "A.java").write_text(f"class A {{ /* {text} */ }}\n", encoding="utf-8")
            self._git("add", "-A", cwd=origin)
            self._git("commit", "-q", "-m", text, cwd=origin)
            commits.append(self._git("rev-parse", "HEAD", cwd=origin))
        return origin, commits

    def _extractor(self, root: Path) -> SingleCsvMethodExtractor:
        return SingleCsvMethodExtractor(output_dir=str(root / "clones"),
                                        methods_output_dir=str(root / "methods"))

    def test_an_older_commit_is_checked_out_and_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            origin, (first, _second) = self._origin(root)
            clone = root / "clone"
            self._git("clone", "-q", "--depth", "1", f"file://{origin}", str(clone), cwd=root)
            extractor = self._extractor(root)
            extractor.apk_revisions = {"app.apk": first[:10]}
            self.assertTrue(extractor._apply_revision_pin(clone, "app.apk"))
            self.assertEqual(extractor.checked_out_revisions["app.apk"], first)
            self.assertNotIn("app.apk", extractor.unavailable_pins)

    def test_a_missing_commit_is_not_replaced_by_the_default_branch(self):
        from cognalys.llm.finding_discovery import FindingDiscovery

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            origin, (_first, second) = self._origin(root)
            clone = root / "clone"
            self._git("clone", "-q", f"file://{origin}", str(clone), cwd=root)
            extractor = self._extractor(root)
            csv_file = root / "findings.csv"
            csv_file.write_text(
                "apk,repo_url,repo,class,method,message,unique_msg,spec\n"
                "app.apk,https://example.invalid/app,app/app,A,run,m,unique-a,MessageDigestSpec\n",
                encoding="utf-8")
            extractor.read_csv(str(csv_file))
            extractor.apk_revisions = {"app.apk": "0123456789abcdef0123456789abcdef01234567"}
            self.assertFalse(extractor._apply_revision_pin(clone, "app.apk"))
            self.assertIn("0123456789ab", extractor.unavailable_pins["app.apk"])
            # Still where it was, and recorded as such.
            self.assertEqual(extractor.checked_out_revisions["app.apk"], second)
            extractor.cloned_repos = {"app.apk": clone}
            extractor.extract_methods()
            [record_path] = list((root / "methods").rglob("*.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
        metadata = record["extraction_metadata"]
        self.assertEqual(metadata["extraction_status"], "pinned_revision_unavailable")
        self.assertEqual(metadata["checked_out_revision"], second)
        self.assertEqual(record["source_code"]["method_body"], "")
        reason = FindingDiscovery.unanalysable_reason({
            "extraction_status": metadata["extraction_status"], "method_body": ""})
        self.assertIn("could not be checked out", reason)


class InterruptedCloneTests(unittest.TestCase):
    """A clone that ran out of time is finished, not thrown away.

    The cost of a --depth 1 --filter=blob:none clone is writing the working
    tree across the WSL 9p bridge, not the network, and the measured rate is
    not stable: element-android checks out at ~37 files/s and Signal-Android
    at ~11. Deleting the partial clone made every retry restart from zero, so
    a repository needing more than one timeout could never be cloned however
    many retries were allowed -- three attempts just burned three timeouts.
    """

    def _extractor(self, directory: str) -> SingleCsvMethodExtractor:
        return SingleCsvMethodExtractor(
            output_dir=str(Path(directory) / "out"),
            methods_output_dir=str(Path(directory) / "methods"),
        )

    def test_a_directory_without_a_repository_cannot_be_resumed(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = self._extractor(directory)
            empty = Path(directory) / "empty"
            empty.mkdir()
            self.assertFalse(extractor._resume_partial_clone(empty, "some.apk"))

    def test_a_repository_without_a_valid_head_cannot_be_resumed(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = self._extractor(directory)
            repo = Path(directory) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            self.assertFalse(extractor._resume_partial_clone(repo, "some.apk"))

    def test_an_interrupted_checkout_is_completed_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = self._extractor(directory)
            upstream = Path(directory) / "upstream"
            upstream.mkdir()
            for command in (
                ["git", "init", "-q", "-b", "main"],
                ["git", "config", "user.email", "t@example.invalid"],
                ["git", "config", "user.name", "Test"],
            ):
                subprocess.run(command, cwd=upstream, check=True)
            (upstream / "a.txt").write_text("a", encoding="utf-8")
            (upstream / "b.txt").write_text("b", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=upstream, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "initial"], cwd=upstream, check=True,
            )

            repo = Path(directory) / "repo"
            subprocess.run(
                ["git", "clone", "-q", "--no-checkout", str(upstream), str(repo)],
                check=True, capture_output=True,
            )
            # Exactly the state a timeout leaves: objects present, working
            # tree not yet written.
            self.assertFalse((repo / "a.txt").exists())

            self.assertTrue(extractor._resume_partial_clone(repo, "some.apk"))

            self.assertTrue((repo / "a.txt").is_file())
            self.assertTrue((repo / "b.txt").is_file())

    def _repo_with_commit(self, directory: str) -> Path:
        repo = Path(directory) / "repo"
        repo.mkdir()
        for command in (
            ["git", "init", "-q", "-b", "main"],
            ["git", "config", "user.email", "t@example.invalid"],
            ["git", "config", "user.name", "Test"],
        ):
            subprocess.run(command, cwd=repo, check=True)
        (repo / "src").mkdir()
        (repo / "src" / "A.java").write_text("class A {}", encoding="utf-8")
        (repo / "README.md").write_text("readme", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
        return repo

    def test_a_complete_clone_is_left_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = self._extractor(directory)
            repo = self._repo_with_commit(directory)
            self.assertFalse(extractor._checkout_is_incomplete(repo))

    def test_a_clone_whose_tree_was_never_written_is_detected(self):
        """com.vayunmathur's clone sat like this across runs: a valid .git and
        HEAD, 14,000 files in the commit and one on disk. Extraction indexed 0
        classes and reported the finding as an external dependency."""
        with tempfile.TemporaryDirectory() as directory:
            extractor = self._extractor(directory)
            repo = self._repo_with_commit(directory)
            shutil.rmtree(repo / "src")
            (repo / "README.md").unlink()

            self.assertTrue(extractor._checkout_is_incomplete(repo))

    def test_an_incomplete_reused_clone_is_repaired_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            extractor = self._extractor(directory)
            repo = self._repo_with_commit(directory)
            shutil.rmtree(repo / "src")
            (repo / "README.md").unlink()

            self.assertTrue(extractor._ensure_complete_checkout(repo, "some.apk"))

            self.assertTrue((repo / "src" / "A.java").is_file())
            self.assertTrue((repo / "README.md").is_file())
            self.assertFalse(extractor._checkout_is_incomplete(repo))

    def test_a_directory_git_cannot_read_is_not_called_incomplete(self):
        """An unknown must not read as an absence: a directory this cannot
        interrogate is left exactly as it was."""
        with tempfile.TemporaryDirectory() as directory:
            extractor = self._extractor(directory)
            empty = Path(directory) / "not-a-repo"
            empty.mkdir()
            self.assertFalse(extractor._checkout_is_incomplete(empty))

    def test_the_default_timeout_is_sized_for_the_slowest_measured_repository(self):
        """Signal-Android is 10,366 files at a measured ~11 files/s."""
        with tempfile.TemporaryDirectory() as directory:
            self.assertGreaterEqual(
                self._extractor(directory).clone_timeout, 1800,
            )


if __name__ == "__main__":
    unittest.main()
