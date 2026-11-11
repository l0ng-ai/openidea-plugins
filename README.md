# OpenIDEA community plugins

The registry of community plugins for [OpenIDEA](https://github.com/l0ng-ai/openidea).
Each plugin lives in its author's repository; this repository lists who
publishes what. Its index is merged into OpenIDEA's marketplace (Settings ›
Plugins › Available) within the hour of a change.

Plugins live in their authors' repositories and are listed here. The plugins
in OpenIDEA's `plugins/official/` (`openidea.*`) are examples of how to use the
plugin API, not maintained products; build on them in your own repository.
Changes to the plugin API itself (WIT, SDK, host) go to the
[OpenIDEA repository](https://github.com/l0ng-ai/openidea): open the API PR
there and link the plugin in your repository that uses it.

## How it works

- A **publisher** owns a plugin id prefix: publisher `alice` publishes
  `alice.*`. It lists its Ed25519 public keys and the GitHub accounts that may
  change its entries.
- A **plugin entry** pins one released package: its URL and SHA-256. The
  package is signed with the publisher's key.
- On every change, CI downloads each package, checks its SHA-256, runs
  `openidea-plugin check` (the checks installing runs, against the latest
  OpenIDEA release), verifies its signature against the publisher's keys, and
  publishes `index.json` with copies of the packages in the
  [`index` release](../../releases/tag/index).
- A scheduled run checks every plugin daily against the latest release.

## Publishing a plugin

1. Get `openidea-plugin`: from an OpenIDEA release
   (`openidea-plugin-linux-x86_64.gz`), or
   `cargo install --locked --git https://github.com/l0ng-ai/openidea ide-host --bin openidea-plugin`.
2. Create your key once and keep the file secret:
   `openidea-plugin keygen alice.key` prints the public key.
3. Name your plugin `<publisher>.<name>` in `plugin.toml`, set its
   `categories` (up to 3 of `languages`, `themes`, `icon-themes`, `linters`,
   `vcs`, `ai`, `frameworks`, `tools`, `other`), build and sign it:

   ```sh
   openidea-plugin build
   openidea-plugin pack . --key alice.key --publisher alice
   ```

4. Attach `alice.arthas-0.1.0.oiplugin` to a release of your repository and
   note its SHA-256 (`shasum -a 256 alice.arthas-0.1.0.oiplugin`).
5. Open a pull request here with your publisher (first time only) and the
   plugin entry:

   `publishers/alice.toml`

   ```toml
   name = "Alice"
   owners = ["alice"]                 # GitHub accounts that may change these entries
   keys = ["<public key>"]            # add new keys here; older ones stay valid
   revoked-keys = []                  # keys whose packages must no longer install
   ```

   `plugins/alice.arthas.toml`

   ```toml
   repository = "https://github.com/alice/openidea-arthas"

   [[versions]]
   version = "0.1.0"
   package = "https://github.com/alice/openidea-arthas/releases/download/v0.1.0/alice.arthas-0.1.0.oiplugin"
   sha256 = "<sha-256 of the package file>"
   ```

Optionally, list the project files that make your plugin worth suggesting:
OpenIDEA offers it under "Suggested for This Project" when the open project
has one of them (up to 8 project-relative paths, no globs).

```toml
repository = "https://github.com/alice/openidea-arthas"
suggest = ["pom.xml", "build.gradle.kts"]
```

The marketplace shows the repository as the plugin's homepage when its
manifest names none, and how often its packages were downloaded from the
index release.

A new version is a pull request that adds a `[[versions]]` table. Keep the
earlier ones: each version records the plugin API it needs (its
`engines.openidea`, narrowed to the API its component was built for), and
OpenIDEA installs the newest version it can load, so users of an older
OpenIDEA keep getting the last version built for them. The index keeps only
the newest version per API requirement, so a table you no longer need can go
whenever you like. Removing the file delists the plugin (installed copies keep
working).

## Rules

**Listing.** New publishers and new plugins are reviewed by a maintainer:
the source, the capabilities it asks for and why, and that it doesn't
duplicate an existing plugin (improve that one instead). Version updates by an
owner need passing checks and a maintainer's merge; owners are checked
against the publisher file as it was before the pull request.

A plugin must:

- have a public source repository under an open-source licence, and the
  package must be built from it;
- say in its README what it does, and why it needs each `network:`,
  `process:` or other high-risk capability;
- contain no obfuscated or minified code that isn't built from that source.

**Maintenance.** A plugin that fails the checks against a new OpenIDEA
release is reported in an issue; if no fixed version is listed within 30 days,
it is delisted. Owners can hand a publisher over by adding owners.

**New keys.** Add the new key first in `keys`, keep the old one, and let the
old key vouch for the new one, so people who installed your plugins update to
packages signed with the new key without being asked to confirm a change of
signer:

```sh
openidea-plugin endorse "<new public key>" --key old.key --publisher alice
```

```toml
keys = ["<new public key>", "<old public key>"]

[endorsements]
"<new public key>" = { key = "<old public key>", signature = "<signature it printed>" }
```

A lost or stolen key can't vouch for anything: ask for it to be revoked, and
users confirm the new key when they next update.

**Revocation.** Maintainers revoke plugin versions or keys (in `revoked.toml`
or `revoked-keys`) for malware, a security problem the owner doesn't fix, or a
lost key; OpenIDEA then disables them where they are installed. Owners ask for
it in an issue.

## Files

| Path | What |
| --- | --- |
| `publishers/<id>.toml` | a publisher: name, owners, keys |
| `plugins/<publisher>.<name>.toml` | a plugin's current version |
| `revoked.toml` | `[[plugin]]` entries: `id`, `versions` (empty: all), `reason` |
| `featured.toml` | `plugins`: the maintainers' picks, shown under "Featured" |
| `scripts/registry.py` | the checks and the index skeleton CI runs |
