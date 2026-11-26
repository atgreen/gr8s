package sandbox

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Filesystem rights, from include/uapi/linux/landlock.h.
const (
	accessExecute   = 1 << 0
	accessWriteFile = 1 << 1
	accessReadFile  = 1 << 2
	accessReadDir   = 1 << 3
	accessTruncate  = 1 << 14
	accessIoctlDev  = 1 << 15

	readAccess = accessExecute | accessReadFile | accessReadDir
	// Only these rights apply to a file; a file rule carrying others is EINVAL.
	fileAccess = accessExecute | accessWriteFile | accessReadFile | accessTruncate | accessIoctlDev

	scopeAbstractUnixSocket = 1 << 0
	scopeSignal             = 1 << 1
)

type rulesetAttr struct {
	handledAccessFS  uint64
	handledAccessNet uint64
	scoped           uint64
}

// pathBeneathAttr is the kernel's packed 12-byte struct; the kernel reads
// only that much, so Go's trailing padding is never seen.
type pathBeneathAttr struct {
	allowedAccess uint64
	parentFD      int32
}

// Rule allows Access beneath Path.
type Rule struct {
	Path   string
	Access uint64
}

// LandlockABI returns the kernel's Landlock ABI version, 0 without Landlock.
func LandlockABI() int {
	version, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0,
		unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0
	}
	return int(version)
}

// allAccess is every filesystem right ABI knows, so a ruleset handling it
// denies whatever no rule allows.
func allAccess(abi int) uint64 {
	switch {
	case abi >= 5:
		return 1<<16 - 1
	case abi >= 3:
		return 1<<15 - 1
	case abi >= 2:
		return 1<<14 - 1
	default:
		return 1<<13 - 1
	}
}

// ruleAccess narrows access to what Landlock accepts on path: file rights
// only, when path is not a directory.
func ruleAccess(path string, access uint64) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		access &= fileAccess
	}
	return access, nil
}

// RestrictSelf confines the calling thread to rules. Rules whose path does
// not exist are skipped. The caller must hold its OS thread and exec from it.
func RestrictSelf(abi int, rules []Rule) error {
	if abi < 1 {
		return fmt.Errorf("this kernel has no Landlock; refusing to run unconfined")
	}
	handled := allAccess(abi)
	attr := rulesetAttr{handledAccessFS: handled}
	size := unsafe.Sizeof(attr.handledAccessFS)
	switch {
	case abi >= 6:
		attr.scoped = scopeAbstractUnixSocket | scopeSignal
		size = unsafe.Sizeof(attr)
	case abi >= 4:
		size = unsafe.Offsetof(attr.scoped)
	}
	ruleset, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), size, 0)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	defer unix.Close(int(ruleset))

	for _, rule := range rules {
		access, err := ruleAccess(rule.Path, rule.Access&handled)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := addPathRule(int(ruleset), rule.Path, access); err != nil {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

func addPathRule(ruleset int, path string, access uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("opening %s for a Landlock rule: %w", path, err)
	}
	defer unix.Close(fd)
	attr := pathBeneathAttr{allowedAccess: access, parentFD: int32(fd)}
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset),
		unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("landlock_add_rule %s: %w", path, errno)
	}
	return nil
}
