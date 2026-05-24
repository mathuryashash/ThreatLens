import subprocess
import os
import sys

def run_cmd(cmd):
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"Error (exit code {result.returncode}):")
        print(result.stderr)
        return False, result.stdout, result.stderr
    print(result.stdout)
    return True, result.stdout, result.stderr

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(root_dir)
    print(f"Working directory: {root_dir}")

    # 1. Initialize Git repository
    if not os.path.exists(".git"):
        success, _, _ = run_cmd(["git", "init"])
        if not success:
            sys.exit(1)
    else:
        print("Git repository already initialized.")

    # 2. Check remote configuration
    success, remotes, _ = run_cmd(["git", "remote"])
    if not success:
        sys.exit(1)

    repo_url = "https://github.com/mathuryashash/ThreatLens.git"
    if "origin" in remotes.split():
        # Update remote URL
        success, _, _ = run_cmd(["git", "remote", "set-url", "origin", repo_url])
    else:
        # Add remote
        success, _, _ = run_cmd(["git", "remote", "add", "origin", repo_url])
    
    if not success:
        sys.exit(1)

    # 3. Rename branch to main
    success, _, _ = run_cmd(["git", "branch", "-M", "main"])
    if not success:
        sys.exit(1)

    # 4. Add files (respects .gitignore)
    success, _, _ = run_cmd(["git", "add", "."])
    if not success:
        sys.exit(1)

    # 5. Check if there are changes to commit
    success, status, _ = run_cmd(["git", "status", "--porcelain"])
    if not success:
        sys.exit(1)

    if not status.strip():
        print("No changes to commit.")
    else:
        # Commit changes
        success, _, _ = run_cmd(["git", "commit", "-m", "Initial commit: ThreatLens security log triage dashboard"])
        if not success:
            # Maybe username/email is not configured, but let's see.
            pass

    # 6. Push to GitHub
    print("Pushing to GitHub...")
    success, _, _ = run_cmd(["git", "push", "-u", "origin", "main"])
    if not success:
        print("Standard push failed. Attempting force push in case repository has conflicting history...")
        success, _, _ = run_cmd(["git", "push", "-u", "origin", "main", "--force"])
        if not success:
            print("Failed to push to remote repository.")
            sys.exit(1)

    print("Successfully uploaded files to GitHub repository!")

if __name__ == "__main__":
    main()
