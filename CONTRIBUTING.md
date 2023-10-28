# How to contribute

This guide covers how you can become a part of the ongoing develpment of NanoMQ. We welcome every contribution to prosper the NanoMQ community.

### Did you find a bug?

* Ensure the bug was not already reported. Before you report a bug please search on GitHub [Issues](https://github.com/emqx/nanomq/issues) first.

* If you're unable to find an open issue addressing the problem, [open a new issue](https://github.com/emqx/nanomq/issues/new/choose) of bug report.
 You can use the bug report template to create an issue. Be sure to include a title and clear description, and as much relevant information as possible.

### Did you write a patch that fix a bug?

* Open a new GitHub pull request with the patch. If you are new to contribute check [Steps to contribute](#steps-to-contribute).
  
* Ensure the PR description clearly describes the problem and solution.


### Do you intend to add a new feature or change an exsiting one?

* If you plan to do something more involved, first [open a new issue](https://github.com/emqx/nanomq/issues/new/choose) of feature request to disscuss your idea.
 This will avoid unnecessary work and surely give you and us a good deal of inspiration.
  
* Before you make changes to NanoMQ to create your own project, you may check [guidance](./CodeGuidance.md) to learn more about NanoMQ source code.

* We will be glad if you can share your code with the NanoMQ project. This will surely inspire the NanoMQ community and the open-source world.

### Do you have questions about the source code?

* Ask any question about NanoMQ in [discussion](https://github.com/emqx/nanomq/discussions).
  
* You can check [guidance](./CodeGuidance.md) to learn more.

## Steps to Contribute

Here are some steps to create your own forked repository and open a new GitHub pull request.

### First time setup

We use GitHub pull request to review proposed code changes. So you need to obtain a GitHub account before making code contribution.

1. **Fork** NanoMQ to your private repository. Click the `Fork` button in the top right corner of NanoMQ repository.
2. **Clone** the repository locally from your personal fork. `git clone https://github.com/<Github_user>/nanomq.git`.
3. Add NanoMQ repo as additional Git remote so that you can sync between local repo and NanoMQ.

```shell
git remote add upstream https://github.com/emqx/nanomq.git
```

### Create a branch to work on

You’ll work on your contribution in a branch in your own (forked) repository. Create a local branch, initialized with
the state of the branch you expect your changes to be merged into. The `master` branch is the active development branch, so
it is recommended to set `master` as base branch.

```shell
git fetch upstream
git checkout -b <my-branch> upstream/master
```

Now you can use your favorite IDE or editor to make change happens.

### Testing

NanoMQ project leverages Github actions to run unit test & FVT (functional verification test), so please take a
look at the PR status result, and make sure that all testcases run successfully.

You can run the test suit locally in advance.

```shell
cmake .. -DDEBUG=ON -DASAN=ON -DNANOMQ_TESTS=ON <-DCMAKE_BUILD_TYPE=ON>
make
ctest --output-on-failure
```
Note: some tests may fail due to bad Internet connection, you can still submit your commits to run test via Github action.

### Licensing

All code contributed to NanoMQ should be licensed under MIT license. Be sure every new file you have added include the right license header.

### Sign-off commit

Sign-off is required to certify the origin of the commit. If you have set your `user.name` and `user.email` in git configs,
 you can simply use `git commit -s` to sign off your commit. Every commit
must be signed off.

### Syncing

Periodically while you work, and certainly before submitting a pull request, you should update your branch with the most
recent changes to the target branch. We prefer rebase than merge to avoid extraneous merge commits.

```shell
git fetch upstream
git rebase upstream/master
```

### Submitting changes

The `master` branch is the active development branch, so it's recommended to set `master` as base branch, and also create PR
against `master` branch.

Organize your commits to make our reviewing job easier. We prefer multiple small pull requests, instead of a single large pull request.
 Within one pull request, we prefer a relatively small number of commits with logical steps. 
 For most pull requests, it is better to squash your changes down to one commit.

Make sure all your commits comply to the [commit message guidelines](#commit-message-guidelines).

Then you can push to your forked repo. Assume the remove name for your forked is the default `origin`. If you have
rebased the git history before the last push, add `-f` to force pushing the changes.

```shell
git push origin -f
```

Then you can navigate to NanoMQ repo to create a pull request. Our GitHub repo provides automatic testing with GitHub action.
 Please make sure those tests pass. We will review the code after all tests pass.

### Commit Message Guidelines
<!-- this may need further discussion -->

Each commit message start with a '*' and consists of a **tppe**, a **scope** and a **subject**.

```text
* <type> [<scope>] <subject>
```

Examples:

```text
* FIX [bridge] add SUPP_QUIC condition to hybrid protector 
```

```text
* NEW [conf] add new conf params for QUIC
```

#### Type

You can use following types:

- **FIX**: fix a bug, a typo, fix anything.
- **MDF**: refactoring code, format,etc.
- **NEW**: new feature, new docs, new tests, anything new.

#### Scope

There are no predefined scopes for this repository. You can use a custom scope for clarity.

#### Subject

The subject contains a succinct description of the change.

## Community Promotion

There are many other great ways to get involved. We appreciate every contribution to promoting NanoMQ to the open source community.

The promotion contributions include but not limited to:

- Integrating NanoMQ to your own open source project
- Organizing workshops or meetups about the project
- Answering questions about the project on issues, slack or maillist
- Writing tutorials for how the project can be used
- Offering to mentor another contributor

Thank you for your great effort to the NanoMQ community and the open-source world!

