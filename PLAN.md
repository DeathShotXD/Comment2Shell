# Maintenance plan

Comment2Shell is maintained in small, focused commits. One change a day,
each commit doing a single thing and leaving the tree working. That keeps
diffs easy to review and the project moving without a large rewrite
landing all at once.

This is a working plan, not a contract. Items can be reordered or dropped
as the project changes.

## Week 1

- Mon - add `targets.example.txt` with a few sample hosts for `--scan -f`
- Tue - document the JSON output fields in the README
- Wed - add `SECURITY.md` with the disclosure contact and scope
- Thu - add `CHANGELOG.md` starting at 1.0.0
- Fri - tighten `--scan` output when a host is unreachable
- Sat - add a small unit test script for the payload builders
- Sun - README pass: fix typos and tighten wording

## Week 2

- Mon - add `--timeout` notes to the usage section
- Tue - add a `--quiet` flag that suppresses the info lines
- Wed - extend the nuclei template with a second matcher
- Thu - add an ARM64 note to the Docker lab README
- Fri - add a `Makefile` with test and lint targets
- Sat - add OAST callback examples for `--probe`
- Sun - review open issues and label them

## Week 3

- Mon - add a `--rate` limit for batch scans
- Tue - write up the filter chain as `docs/exploit.md`
- Wed - add a lab reset helper beyond `docker/clean.sh`
- Thu - support a custom User-Agent via `--user-agent`
- Fri - add detection notes for classic (non-block) themes
- Sat - add `.gitattributes` for consistent line endings
- Sun - README pass: refresh the demo section

## Week 4

- Mon - add a `--no-color` flag for clean logs
- Tue - add CI that runs the unit tests on push
- Wed - add a release workflow that attaches the script
- Thu - document and test supported Python versions
- Fri - add a short FAQ to the README
- Sat - add `CONTRIBUTING.md`
- Sun - tag the next release

## Commit conventions

- One change per commit, present tense: "add ...", "fix ...", "docs ..."
- Keep the subject under 72 characters, no trailing period
- Do not mix refactors with behaviour changes
- Run the tests before committing

## Daily checklist

1. Pick the next unchecked item.
2. Make the smallest change that completes it.
3. Run the unit tests and `python3 comment2shell.py --scan -t http://localhost`.
4. Commit with a plain, human message.
5. Push to `main`.
