// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWorktreeSharedNamesTheRepositorysGitAndBeads(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	common := filepath.Join(repo, ".git")
	gitdir := filepath.Join(common, "worktrees", "feature")
	worktree := filepath.Join(root, "repo", "build", "wt-feature")
	for _, dir := range []string{gitdir, filepath.Join(repo, ".beads"), filepath.Join(worktree, "src")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+gitdir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitdir, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// From the worktree, or anywhere under it.
	for _, dir := range []string{worktree, filepath.Join(worktree, "src")} {
		got := WorktreeShared(dir)
		want := []string{common, filepath.Join(repo, ".beads")}
		if !slices.Equal(got, want) {
			t.Errorf("WorktreeShared(%q) = %q, want %q", dir, got, want)
		}
	}
	// The main checkout needs nothing more than itself.
	if got := WorktreeShared(repo); got != nil {
		t.Errorf("WorktreeShared(main checkout) = %q, want nil", got)
	}
	// A repository without beads shares only its git directory.
	if err := os.RemoveAll(filepath.Join(repo, ".beads")); err != nil {
		t.Fatal(err)
	}
	if got := WorktreeShared(worktree); !slices.Equal(got, []string{common}) {
		t.Errorf("WorktreeShared without .beads = %q", got)
	}
	// Outside any repository: nothing.
	if got := WorktreeShared(t.TempDir()); got != nil {
		t.Errorf("WorktreeShared(outside) = %q, want nil", got)
	}
}
