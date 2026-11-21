"""A sample nobody can redraw is not a sample anyone can check.

Three things about the selection were unrecorded: the F-Droid catalogue was
downloaded live on every run, so the same input and the same seed produced
different samples as the index changed; the distribution targets were
computed over observations, in which a finding the detector reported twice
counts twice; and the selection is an integer program with no randomisation
at all, which "stratified sampling" does not describe.

None of that is fixed by writing a number down differently. It is fixed by
recording what was used, and by saying plainly which population the targets
were computed over.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

import pandas as pd  # noqa: E402

from cognalys.corpus.filtro_v3 import (  # noqa: E402
    achados_unicos, carregar_catalogo_fdroid, filtrar_e_amostrar,
)


CATALOGUE = json.dumps({"apps": [
    {"packageName": "com.example.one",
     "sourceCode": "https://github.com/owner/one"},
    {"packageName": "com.example.two",
     "sourceCode": "https://github.com/owner/two"},
]})


def _corpus(path: Path) -> None:
    rows = [
        # The same finding reported three times, as the raw corpus does.
        *[{"apk": "com.example.one_v1.0.apk", "spec": "CipherSpec",
           "class": "com.example.one.Crypto", "method": "encrypt",
           "message": "unsafe", "unique_msg": "one-crypto"} for _ in range(3)],
        {"apk": "com.example.two_v2.0.apk", "spec": "KeyStoreSpec",
         "class": "org.other.Store", "method": "load",
         "message": "unsafe", "unique_msg": "two-store"},
    ]
    pd.DataFrame(rows).to_csv(path, index=False)


class UniqueFindingTests(unittest.TestCase):

    def test_repeated_observations_collapse_to_one_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "errors.csv"
            _corpus(corpus)
            frame = pd.read_csv(corpus)
        self.assertEqual(len(frame), 4)
        self.assertEqual(len(achados_unicos(frame)), 2)


class CatalogueProvenanceTests(unittest.TestCase):

    def test_a_snapshot_is_read_instead_of_downloaded(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "index-v1.json"
            snapshot.write_text(CATALOGUE, encoding="utf-8")
            catalogue, provenance = carregar_catalogo_fdroid(snapshot)
        self.assertEqual(len(catalogue), 2)
        self.assertTrue(provenance["fonte"].startswith("snapshot:"))
        self.assertEqual(len(provenance["sha256"]), 64)
        self.assertEqual(provenance["aplicativos"], 2)

    def test_without_a_snapshot_and_without_downloading_it_refuses(self):
        with self.assertRaises(RuntimeError):
            carregar_catalogo_fdroid(None, baixar=False)


class SampleProvenanceTests(unittest.TestCase):

    def test_the_sample_is_written_with_a_provenance_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "errors.csv"
            _corpus(corpus)
            snapshot = root / "index-v1.json"
            snapshot.write_text(CATALOGUE, encoding="utf-8")
            output = root / "sample.csv"
            filtrar_e_amostrar(corpus, output, snapshot)
            provenance = json.loads(
                output.with_suffix(".proveniencia.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(len(provenance["entrada"]["sha256"]), 64)
        self.assertEqual(len(provenance["saida"]["sha256"]), 64)
        self.assertTrue(
            provenance["catalogo_fdroid"]["fonte"].startswith("snapshot:")
        )
        # The two populations are reported side by side, and which one the
        # targets used is stated rather than implied.
        population = provenance["populacao"]
        self.assertEqual(population["observacoes_elegiveis"], 4)
        self.assertEqual(population["achados_unicos"], 2)
        self.assertEqual(
            population["metas_calculadas_sobre"], "observacoes_elegiveis"
        )
        # The method is named for what it is.
        self.assertEqual(
            provenance["selecao"]["metodo"], "programacao_linear_inteira"
        )
        self.assertIn("nenhuma", provenance["selecao"]["aleatoriedade"])
        # And the ownership split carries its own limitation.
        self.assertIn("package", provenance["origem_classe"]["metodo"])
        self.assertIn(
            "coordenada Gradle", provenance["origem_classe"]["limitacao"]
        )


if __name__ == "__main__":
    unittest.main()
