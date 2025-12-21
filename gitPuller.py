#!/usr/bin/env python3

import argparse
import atexit
import os
import subprocess
import sys
import getpass
import tempfile

def current_branch(cwd, env):
    return run_git_command(['rev-parse', '--abbrev-ref', 'HEAD'], cwd, env)


def find_repos(base, depth, current = 0):
    """
    Yield git repository paths.
    depth = 0 means infinite recursion.
    """
    ## yield if a repo
    if os.path.isdir(os.path.join(base, '.git')):
        yield base

    ## depth limits
    if depth != 0 and current >= depth:
        return

    ## subdirs
    for entry in os.scandir(base):
        if entry.is_dir(follow_symlinks = False):
            yield from find_repos(entry.path, depth, current + 1)


def list_all_branches(cwd, env):
    output = run_git_command(['branch', '-a'], cwd, env)
    branches = []
    for line in output.split('\n'):
        branches.append(line.replace('*', '').strip())
    return branches


def list_local_branches(cwd, env):
    output = run_git_command(['branch'], cwd, env)
    return [line.replace('*', '').strip() for line in output.split('\n')]


def process_repo(path, use_all, env):
    """Run the backup routine on a single repository."""
    print(f'{COLOR_GREEN}Processing repository:{COLOR_RESET} {COLOR_BLUE}{path}{COLOR_RESET}')
    if not os.path.isdir(os.path.join(path, '.git')):
        print('Not a git repository. Skipping.')
        return

    ## Notate current branch
    original_branch = None
    try:
        original_branch = current_branch(path, env)
    except Exception:
        pass

    ## branch discovery mode
    if use_all:
        branches = list_all_branches(path, env)
        remote_branches = [b for b in branches if b.startswith('origin/') and '->' not in b]
        local_branches = list_local_branches(path, env)
    else:
        local_branches = list_local_branches(path, env)
        remote_branches = []

    ## local branches
    for br in local_branches:
        try:
            run_git_command(['checkout', br], path, env)
            pull_branch(br, path, env)
        except Exception as e:
            PROBLEM_REPOS.append((path, f"local branch '{br}'", str(e)))
            print(f"{COLOR_RED}[!] Error on {path} branch {br}. Continuing...{COLOR_RESET}")

    ## for --all
    if use_all:
        for remote in remote_branches:
            local_equiv = remote.split('/', 1)[1]
            if local_equiv not in local_branches:
                print(f'\n--- Creating local branch {local_equiv} from {remote} ---')
                try:
                    run_git_command(['checkout', '-b', local_equiv, remote], path, env)
                    pull_branch(local_equiv, path, env)
                except Exception as e:
                    PROBLEM_REPOS.append((path, f"remote '{remote}'", str(e)))
                    print(f"{COLOR_RED}[!] Error creating/updating {local_equiv} from {remote}. Continuing...{COLOR_RESET}")

    ## Revert to original branch
    if original_branch:
        try:
            run_git_command(['checkout', original_branch], path, env)
            print(f'{COLOR_BLUE}[~] Restored branch {original_branch}{COLOR_RESET}')
        except Exception as e:
            PROBLEM_REPOS.append((path, 'restore branch', str(e)))
            print(f'{COLOR_RED}[!] Failed to restore branch {original_branch}{COLOR_RESET}')


def pull_branch(branch, cwd, env):
    print(f'Pulling latest for {branch}...')
    try:
        # First attempt: without credentials
        result = subprocess.run(['git', 'pull'],
                                cwd = cwd,
                                text = True,
                                env = os.environ,
                                capture_output = False,
                                check = True)
        return
    except subprocess.CalledProcessError as E:
        stderr = E.stderr or ''

        ## tracking handling
        no_tracking = 'There is no tracking information for the current branch' in stderr

        if no_tracking:
            msg = f'No upstream tracking branch for {branch} in {cwd}'
            PROBLEM_REPOS.append((cwd, f"branch '{branch}'", msg))
            print(f'{COLOR_YELLOW}[!] {msg}. Skipping pull.{COLOR_RESET}')
            return

        ## find auth fails
        auth_fail = any(msg in stderr for msg in ['Authentication failed',
                                                  'fatal: could not read',
                                                  'Permission denied',
                                                  'publickey',
                                                  'returned error: 403',
                                                  'returned error: 401'])

        ## pull error handling
        if not auth_fail:
            msg = f'Pull error on {cwd} branch {branch}: {stderr}'
            PROBLEM_REPOS.append((cwd, f"branch '{branch}'", msg))
            print(f'{COLOR_RED}[!] {msg}{COLOR_RESET}')
            return

        print(f'{COLOR_YELLOW}[!] Authentication required for {cwd}{COLOR_RESET}')

        if not env:
            msg = f'No credentials provided to pull {branch} in {cwd}'
            PROBLEM_REPOS.append((cwd, f"branch '{branch}'", msg))
            print(f'{COLOR_RED}[!] {msg}{COLOR_RESET}')
            return

        print(f'{COLOR_BLUE}[~] Retrying with provided credentials...{COLOR_RESET}')

        try:
            subprocess.run(['git', 'pull'],
                           cwd = cwd,
                           text = True,
                           env = {**os.environ, **env},
                           capture_output = True,
                           check = True)
            print(f'{COLOR_GREEN}[+] Pull succeeded with credentials.{COLOR_RESET}')

        except subprocess.CalledProcessError as E2:
            msg = f'Pull failed with credentials in {cwd} on branch {branch}:\n{E2.stderr}'
            PROBLEM_REPOS.append((cwd, f"branch '{branch}'", msg))
            print(f'{COLOR_RED}[!] {msg}{COLOR_RESET}')


def run_git_command(args, cwd, env = None, check = True):
    """Run a git command with optional environment."""
    env_vars = os.environ.copy()
    if env:
        env_vars.update(env)

    try:
        result = subprocess.run(['git'] + args,
                                cwd = cwd,
                                text = True,
                                capture_output = True,
                                check = check,
                                env = env_vars)
        return result.stdout.strip()

    ## make the issue known
    except subprocess.CalledProcessError as E:
        raise RuntimeError(f"Git command failed in {cwd}: git {' '.join(args)}\n stdout: {E.stdout}\nstderr: {E.stderr}")


def sshEnv():
    print('[~] Starting ssh-agent')
    result = subprocess.run(['ssh-agent', '-s'],
                            text = True,
                            capture_output = True,
                            check = True)

    ## output parsing
    env = {}
    for line in result.stdout.splitlines():
        if line.startswith('SSH_AUTH_SOCK'):
            env['SSH_AUTH_SOCK'] = line.split(';', 1)[0].split('=', 1)[1]
        elif line.startswith('SSH_AGENT_PID'):
            env['SSH_AGENT_PID'] = line.split(';', 1)[0].split('=', 1)[1]

    ## env handler
    print('[~] Adding SSH key')
    os.environ.update(env)
    subprocess.run(['ssh-add'], check = True)
    print('[+] SSH agent ready.\n')
    return env


def main():
    parser = argparse.ArgumentParser(description = 'Backup Git repositories.')
    parser.add_argument('--all',
                        action = 'store_true',
                        help = 'Backup ALL branches, including remote-only ones.')
    parser.add_argument('-p',
                        action = 'store_true',
                        help = 'Use password for credentials')
    parser.add_argument('-s',
                        action = 'store_true',
                        help = 'Use an SSH key for credentials')
    parser.add_argument('-r',
                        type = int,
                        nargs = '?',
                        const = 1,
                        default = None,
                        help = 'Recurse N levels deep. Use 0 for infinite recursion. Default without value = 1.')
    args = parser.parse_args()

    ## env setup
    base_dir = os.getcwd()
    env = {}

    ## credential handling
    askpass_path = None  # define before conditional
    if args.p:
        password = getpass.getpass('Enter your Git password: ')
        with tempfile.NamedTemporaryFile(delete = False, mode = 'w') as f:
            askpass_path = f.name
            f.write(f"#!/bin/sh\necho '{password}'\n")
        os.chmod(askpass_path, 0o700)
        env = {'GIT_ASKPASS': askpass_path, 'SSH_ASKPASS': askpass_path}

        # Register cleanup
        import atexit
        atexit.register(lambda: os.remove(askpass_path) if askpass_path else None)
    if args.s:
        env = sshEnv()

    ## recursion handling      
    if args.r is None:
        process_repo(base_dir, args.all, env)
    else:
        depth = args.r
        if depth == 0:
            print('Recursing infinitely...\n')
        else:
            print(f'Recursing {depth} level(s) deep...\n')

        for repo in find_repos(base_dir, depth):
            process_repo(repo, args.all, env)
    print('\n[~] All backups complete!')

    if PROBLEM_REPOS:
        print(f'\n{COLOR_YELLOW}[!] Some repositories had issues:{COLOR_RESET}\n')
        for repo, item, err in PROBLEM_REPOS:
            print(f'{COLOR_RED}- Repo:{COLOR_RESET} {repo}')
            print(f'  Problem item: {item}')
            print(f'  Error: {err}\n')
    else:
        print(f'{COLOR_GREEN}[+] No issues encountered.{COLOR_RESET}')


# ANSI color helpers
COLOR_BLUE = '\033[94m'
COLOR_GREEN = '\033[92m'
COLOR_YELLOW = '\033[93m'
COLOR_RED = '\033[91m'
COLOR_RESET = '\033[0m'

PROBLEM_REPOS = []

if __name__ == '__main__':
    main()
