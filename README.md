# Luddite Scout action

Runs [Luddite Scout](https://github.com/TechLuddite/Luddite-Scout)'s static checks on a pull request checkout, on GitHub Actions and Gitea Actions. It reads files and runs nothing from the repository, not even `git`.

**Status:** experimental.

## Use

GitHub Actions, `.github/workflows/scout.yml`:

```yaml
name: scout

on: pull_request

permissions:
  contents: read

jobs:
  scout:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - uses: TechLuddite/luddite-scout-action@<full commit SHA>
        with:
          name: ${{ github.repository }}
          commit: ${{ github.event.pull_request.head.sha }}
```

Gitea Actions takes the same file under `.gitea/workflows/`. The job image needs `bash` and `python3` for this action, and Node.js for `actions/checkout`. Gitea fetches `TechLuddite/luddite-scout-action` from the instance's `DEFAULT_ACTIONS_URL`, so an instance set to `self` needs a mirror of this repository that holds the pinned commit.

Three things in that workflow matter:

1. **Pin the action to a full commit SHA.** Never use `uses: ./` or a branch from the repository under review, or a pull request can replace the scanner and pass itself.
2. **Check out the pull request head**, which is the commit you pass as `commit`. On GitHub the default `pull_request` checkout is a merge commit.
3. **Scan straight after checkout**, before installing dependencies or building. The scan reads the directory as it is on disk, including untracked files.

Use `on: pull_request`, not `pull_request_target`. The action needs no token and no secrets.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Directory to scan |
| `fail-on` | `high` | Fail on a finding at or above `info`, `low`, `medium` or `high`, or `never` |
| `fail-on-incomplete` | `true` | Fail when a check was skipped or only partly covered, for example a file over a read limit. Ignored when `fail-on` is `never` |
| `name` | directory name | Repository name for the report |
| `commit` | none | Full commit SHA for the report |

The output `report` is the path to the JSON report. The readable report goes to the job log, with workflow commands turned off while it prints, and to the job summary where the runner supports one.

## What it checks

The same checks as Luddite Scout, through `bin/scout --dir`: agent instruction files (S2), hidden Unicode (S3), GitHub, Gitea and Forgejo workflows and composite actions (S4), lockfiles against OSV (S5), build-time code (S6) and Omarchy plugin rules (S7). Repository settings (S1) need the GitHub API and are not checked. S5 sends package names and versions from lockfiles to `api.osv.dev`. Nothing else leaves the runner.

Findings are pattern matches for a person to judge. A clean report is not proof that a repository is safe.

## How the scanner is pinned

`bin/scout` is a copy of Luddite Scout's scanner at the commit in `scout.lock`. `./check-vendor.sh` checks its SHA-256 against the lock, and `./check-vendor.sh --upstream` also compares it with Luddite Scout at that commit. CI runs both. To move to a newer scanner, copy `bin/scout` from that commit and update `commit` and `sha256` together.

## Development

```sh
python3 -m unittest discover -s test
./check-vendor.sh --upstream
```

## Licence

MIT
