// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"strings"
)

// WorktreeShared is what a command run in a git worktree at dir needs beyond the
// worktree itself: the repository's shared git directory, where its objects and refs
// live, and the state tools keep beside the main checkout, such as beads' database.
// Neither is under the worktree, so a sandbox granting only the working directory
// left git unable to commit and bd silently starting an empty database there
// (podster-0ii.10). Empty outside a worktree, where the working directory holds both.
func WorktreeShared(dir string) []string {
	for current := dir; ; current = filepath.Dir(current) {
		marker := filepath.Join(current, ".git")
		info, err := os.Stat(marker)
		if err == nil {
			if info.IsDir() {
				return nil // a main checkout: everything it uses is under it
			}
			return worktreeShared(current, marker)
		}
		if parent := filepath.Dir(current); parent == current {
			return nil
		}
	}
}

func worktreeShared(worktree, marker string) []string {
	content, err := os.ReadFile(marker)
	if err != nil {
		return nil
	}
	line := strings.TrimSpace(string(content))
	if !strings.HasPrefix(line, "gitdir:") {
		return nil
	}
	gitdir := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
	if !filepath.IsAbs(gitdir) {
		gitdir = filepath.Join(worktree, gitdir)
	}
	// A linked worktree's gitdir names the shared one in its commondir file.
	common := gitdir
	if relative, err := os.ReadFile(filepath.Join(gitdir, "commondir")); err == nil {
		common = strings.TrimSpace(string(relative))
		if !filepath.IsAbs(common) {
			common = filepath.Join(gitdir, common)
		}
	}
	common = filepath.Clean(common)
	shared := []string{common}
	if filepath.Base(common) == ".git" {
		if beads := filepath.Join(filepath.Dir(common), ".beads"); isDirectory(beads) {
			shared = append(shared, beads)
		}
	}
	return shared
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
