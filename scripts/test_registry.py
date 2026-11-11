import base64
import io
import unittest
import urllib.error
from unittest import mock

import registry as r

KEY = base64.b64encode(bytes(32)).decode()
SHA = "0" * 64


def publisher(owners='["alice"]'):
    return f'name = "Alice"\nowners = {owners}\nkeys = ["{KEY}"]\n'


def plugin(*versions, package="https://example.com/a.oiplugin"):
    tables = "".join(
        f'\n[[versions]]\nversion = "{v}"\npackage = "{package}"\nsha256 = "{SHA}"\n' for v in versions or ["0.1.0"]
    )
    return 'repository = "https://github.com/alice/arthas"\n' + tables


class Load(unittest.TestCase):
    def test_a_valid_registry(self):
        reg = r.load({"publishers/alice.toml": publisher(), "plugins/alice.arthas.toml": plugin()})
        self.assertEqual(reg.plugins["alice.arthas"].versions[0].file, "alice.arthas-0.1.0.oiplugin")
        skeleton = r.index_skeleton(reg)
        self.assertEqual(skeleton["publishers"][0]["keys"], [{"key": KEY, "revoked": False}])

    def test_endorsements_pass_into_the_index(self):
        new = base64.b64encode(bytes([1]) * 32).decode()
        sig = base64.b64encode(bytes(64)).decode()
        text = (
            f'name = "Alice"\nowners = ["alice"]\nkeys = ["{new}", "{KEY}"]\n'
            f'[endorsements]\n"{new}" = {{ key = "{KEY}", signature = "{sig}" }}\n'
        )
        reg = r.load({"publishers/alice.toml": text})
        keys = r.index_skeleton(reg)["publishers"][0]["keys"]
        self.assertEqual(keys[0], {"key": new, "revoked": False, "endorsement": {"key": KEY, "signature": sig}})
        self.assertEqual(keys[1], {"key": KEY, "revoked": False})
        other = base64.b64encode(bytes([2]) * 32).decode()
        for bad, expected in [
            (f'[endorsements]\n"{KEY}" = {{ key = "{KEY}", signature = "{sig}" }}\n', "another of"),
            (f'[endorsements]\n"{other}" = {{ key = "{KEY}", signature = "c2hvcnQ=" }}\n', "not an Ed25519 signature"),
            (f'[endorsements]\n"{new}" = {{ key = "{KEY}", signature = "{sig}" }}\n', "must be in `keys`"),
            (f'[endorsements]\n"{KEY}" = {{ key = "{new}" }}\n', "needs `key` and `signature`"),
        ]:
            with self.assertRaises(r.Invalid) as e:
                r.load({"publishers/alice.toml": publisher().replace(f'["{KEY}"]', f'["{KEY}", "{other}"]') + bad})
            self.assertIn(expected, str(e.exception))

    def test_problems_are_all_reported(self):
        files = {
            "publishers/Bad.toml": publisher(),
            "publishers/bob.toml": 'name = "Bob"\nowners = ["bob"]\nkeys = ["short"]\n',
            "plugins/carol.x.toml": plugin(),
            "plugins/alice.toml": plugin(),
            "plugins/alice.y.toml": plugin("1"),
            "plugins/alice.w.toml": plugin("1.0.0", "1.0.0"),
            "plugins/alice.v.toml": 'repository = "https://github.com/alice/v"\n',
            "plugins/alice.z.toml": plugin(package="http://example.com/z"),
            "publishers/alice.toml": publisher(),
            "revoked.toml": '[[plugin]]\nid = "dave.x"\nreason = "malware"\n',
        }
        with self.assertRaises(r.Invalid) as e:
            r.load(files)
        message = str(e.exception)
        for expected in [
            "publishers/Bad.toml",
            "not an Ed25519 public key",
            "no publishers/carol.toml",
            "plugins/alice.toml: the file name",
            "semver",
            "listed twice",
            "`[[versions]]` table",
            "https URL",
            "dave.x is not a plugin",
        ]:
            self.assertIn(expected, message)


class Review(unittest.TestCase):
    base = r.load({"publishers/alice.toml": publisher(), "plugins/alice.arthas.toml": plugin()})

    def test_owners_update_their_plugins(self):
        head = r.load(
            {"publishers/alice.toml": publisher(), "plugins/alice.arthas.toml": plugin("0.2.0", "0.1.0")}
        )
        problems, notes = r.review(self.base, head, ["plugins/alice.arthas.toml"], "alice")
        self.assertEqual(problems, [])
        self.assertEqual(notes, ["`alice.arthas` +0.2.0"])

    def test_others_cannot_change_them_or_add_themselves_as_owners(self):
        head = r.load(
            {"publishers/alice.toml": publisher('["alice", "mallory"]'), "plugins/alice.arthas.toml": plugin("0.2.0")}
        )
        changed = ["publishers/alice.toml", "plugins/alice.arthas.toml"]
        problems, _ = r.review(self.base, head, changed, "mallory")
        self.assertEqual(len(problems), 2)
        self.assertEqual(r.review(self.base, head, changed, "l0ng-ai")[0], [])

    def test_a_new_publisher_is_noted_and_owned_by_its_author(self):
        files = {
            "publishers/alice.toml": publisher(),
            "plugins/alice.arthas.toml": plugin(),
            "publishers/bob.toml": publisher('["bob"]'),
            "plugins/bob.tool.toml": plugin(),
        }
        head = r.load(files)
        changed = ["publishers/bob.toml", "plugins/bob.tool.toml"]
        problems, notes = r.review(self.base, head, changed, "bob")
        self.assertEqual(problems, [])
        self.assertEqual(notes, ["new publisher `bob`", "new plugin `bob.tool`"])
        self.assertTrue(r.review(self.base, head, changed, "mallory")[0])

    def test_other_files_are_the_maintainers(self):
        problems, _ = r.review(self.base, self.base, ["scripts/registry.py", "revoked.toml"], "alice")
        self.assertEqual(len(problems), 2)


class DownloadRetry(unittest.TestCase):
    @staticmethod
    def reply(code=None, body=b"x"):
        if code is None:
            resp = mock.MagicMock()
            resp.__enter__.return_value.read.return_value = body
            return resp
        return urllib.error.HTTPError("u", code, "m", {}, io.BytesIO())

    def run_download(self, outcomes):
        sleeps = []
        with mock.patch("urllib.request.urlopen", side_effect=outcomes):
            return r.download("https://example.com/p", sleep=sleeps.append), sleeps

    def test_retries_a_gateway_timeout(self):
        data, sleeps = self.run_download([self.reply(504), self.reply(502), self.reply()])
        self.assertEqual(data, b"x")
        self.assertEqual(len(sleeps), 2)

    def test_not_found_is_none_without_retry(self):
        data, sleeps = self.run_download([self.reply(404)])
        self.assertIsNone(data)
        self.assertEqual(sleeps, [])

    def test_client_errors_are_not_retried(self):
        with self.assertRaises(urllib.error.HTTPError):
            self.run_download([self.reply(403)])

    def test_gives_up_after_the_last_attempt(self):
        with self.assertRaises(urllib.error.HTTPError):
            self.run_download([self.reply(504)] * r.RETRIES)

if __name__ == "__main__":
    unittest.main()


class Annotate(unittest.TestCase):
    def registry(self, **files):
        base = {"publishers/alice.toml": publisher(), "plugins/alice.arthas.toml": plugin()}
        base["plugins/alice.arthas-x.toml"] = 'suggest = ["pom.xml", "config/routes.rb"]\n' + plugin()
        return r.load({**base, **files})

    def test_listing_details_join_the_index(self):
        reg = self.registry(**{"featured.toml": 'plugins = ["alice.arthas-x"]\n'})
        index = {
            "plugins": [
                {"id": "alice.arthas", "homepage": "https://arthas.dev"},
                {"id": "alice.arthas-x"},
                {"id": "openidea.csv"},
            ]
        }
        assets = [
            {"name": "alice.arthas-0.1.0.oiplugin", "downloadCount": 3},
            {"name": "alice.arthas-0.2.0.oiplugin", "downloadCount": 4},
            {"name": "alice.arthas-x-1.0.0.oiplugin", "downloadCount": 10},
            {"name": "index.json", "downloadCount": 99},
        ]
        a, x, official = r.annotate(index, reg, assets)["plugins"]
        self.assertEqual(a, {"id": "alice.arthas", "homepage": "https://arthas.dev", "downloads": 7})
        self.assertEqual(
            x,
            {
                "id": "alice.arthas-x",
                "homepage": "https://github.com/alice/arthas",
                "suggest": ["pom.xml", "config/routes.rb"],
                "featured": True,
                "downloads": 10,
            },
        )
        self.assertEqual(official, {"id": "openidea.csv"})

    def test_suggestions_stay_inside_the_project(self):
        for bad in ['["../pom.xml"]', '["/etc/hosts"]', '["*.php"]', '["a//b"]', str([f"f{i}" for i in range(9)])]:
            with self.assertRaises(r.Invalid) as e:
                r.load({"publishers/alice.toml": publisher(), "plugins/alice.a.toml": f"suggest = {bad}\n" + plugin()})
            self.assertIn("`suggest`", str(e.exception))

    def test_featured_lists_listed_plugins_only(self):
        with self.assertRaises(r.Invalid) as e:
            self.registry(**{"featured.toml": 'plugins = ["alice.gone"]\n'})
        self.assertIn("alice.gone is not a listed plugin", str(e.exception))

    def test_only_maintainers_pick(self):
        base, head = self.registry(), self.registry(**{"featured.toml": 'plugins = ["alice.arthas"]\n'})
        problems, _ = r.review(base, head, ["featured.toml"], "alice")
        self.assertEqual(problems, ["featured.toml: only maintainers change this file"])
