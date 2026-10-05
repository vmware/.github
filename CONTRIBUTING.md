# Contributing

We welcome contributions from the community, and thank you for taking the time to contribute!

This is the default contributing guide for repositories in the `vmware` GitHub organization. If a repository has its own `CONTRIBUTING.md`, that file takes precedence. For how to build, run and test a particular project, see that repository's README.

Please read the [Code of Conduct](https://github.com/vmware/.github/blob/main/CODE_OF_CONDUCT.md) before contributing.

## Ways to contribute

We welcome many different types of contributions, and not all of them need a pull request. Contributions may include:

* New features and proposals
* Documentation
* Bug fixes
* Issue triage
* Answering questions and giving feedback
* Helping to onboard new contributors

## Signing the CLA or DCO

Before a pull request can be merged, its author must sign either the Contributor License Agreement (CLA) or the Developer Certificate of Origin (DCO). Which one is decided automatically from the repository's license — you don't need to work it out yourself. The pull request's **Check CLA/DCO** status shows which document applies.

**DCO.** Sign off every commit with `git commit -s`, which adds a `Signed-off-by: Your Name <you@example.com>` line to the commit message. If every commit in the pull request is signed off, the check passes with no further action. Read the [Developer Certificate of Origin](https://vmware.github.io/oss-public-policy/DCO_1.1).

**CLA.** Read the [Broadcom Contributor License Agreement](https://vmware.github.io/oss-public-policy/Broadcom_CLA), then post this as a new comment on your pull request:

```text
I have read the CLA Document and I hereby sign the CLA for this and all future contributions.
```

If the check fails, a bot comments on your pull request with the exact sentence to post — for a DCO repository whose commits aren't all signed off, posting the DCO sentence it gives you works too. Copy the sentence exactly. The check updates automatically, usually within 15–20 minutes, and you don't need to ask a maintainer.

Signing is a one-time step per GitHub account. It covers every repository in this organization that requires the same document. The CLA and DCO are tracked separately, so signing one does not cover the other.

If the check reads something like **CLA Missing (DCO text posted)**, you posted the sentence for the other document. Post the sentence for the document named first.

## Contribution flow

This is a rough outline of a contributor's workflow:

* Fork the repository into your GitHub account
* Create a topic branch in your fork from the branch you want to base your work on
* Make commits of logical units
* Write clear, descriptive commit messages (see below)
* Push your changes to the topic branch in your fork
* Open a pull request against the repository's default branch

We follow the GitHub workflow; see the [GitHub flow documentation](https://docs.github.com/en/get-started/using-github/github-flow) for details.

### Pull request checklist

1. Check that your changes pass the project's linting checks and tests.
2. Ensure your commit messages are descriptive. We follow the conventions in [How to Write a Git Commit Message](https://cbea.ms/git-commit/). Include any related GitHub issue references in the commit message — see [referencing issues and pull requests](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#referencing-issues-and-pull-requests).
3. Check your commits and commit messages for typos.

## Reporting bugs and creating issues

Open an issue in the relevant repository, following its issue template if it has one.

**Do not report security vulnerabilities in public issues.** Email [vmware.psirt@broadcom.com](mailto:vmware.psirt@broadcom.com) or use the repository's **Report a vulnerability** button instead — see the [security policy](https://github.com/vmware/.github/blob/main/SECURITY.md).

## Ask for help

The best place to ask a question about a contribution is the related GitHub issue or pull request.
