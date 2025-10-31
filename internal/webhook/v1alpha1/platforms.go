package v1alpha1

import (
	"fmt"
	"slices"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// The current validator was developed based on the OCI image spec:
// https://specs.opencontainers.org/image-spec/image-index/

// validPlatforms maps OS to supported architectures
var validPlatforms = map[string][]string{
	"aix":       {"ppc64"},
	"android":   {"386", "amd64", "arm", "arm64"},
	"darwin":    {"amd64", "arm64"},
	"dragonfly": {"amd64"},
	"freebsd":   {"386", "amd64", "arm"},
	"illumos":   {"amd64"},
	"ios":       {"arm64"},
	"js":        {"wasm"},
	"linux":     {"386", "amd64", "arm", "arm64", "loong64", "mips", "mipsle", "mips64", "mips64le", "ppc64", "ppc64le", "riscv64", "s390x"},
	"netbsd":    {"386", "amd64", "arm"},
	"openbsd":   {"386", "amd64", "arm", "arm64"},
	"plan9":     {"386", "amd64", "arm"},
	"solaris":   {"amd64"},
	"wasip1":    {"wasm"},
	"windows":   {"386", "amd64", "arm", "arm64"},
}

// allowedVariants maps architecture to valid variants
var allowedVariants = map[string][]string{
	"arm":   {"v6", "v7", "v8"},
	"arm64": {"v8"},
}

// validatePlatform checks if the platform is valid
func validatePlatform(p v1alpha1.Platform) error {
	// Check if OS is supported
	arches, ok := validPlatforms[p.OS]
	if !ok {
		return fmt.Errorf("unsupported OS: %s", p.OS)
	}

	// Check if arch is valid for this OS
	if !slices.Contains(arches, p.Architecture) {
		return fmt.Errorf("unsupported arch %s for OS %s", p.Architecture, p.OS)
	}

	// Check variant
	variants, hasVariants := allowedVariants[p.Architecture]
	if hasVariants {
		// if the arch has a variant (but no variant is provided by the user),
		// we consider it as a valid platform.
		// eg. linux/arm is a valid platform
		if p.Variant != "" && !slices.Contains(variants, p.Variant) {
			return fmt.Errorf("invalid variant %s for arch %s (allowed: %v)", p.Variant, p.Architecture, variants)
		}
	} else if p.Variant != "" {
		// This arch doesn't support variants but one was provided
		return fmt.Errorf("arch %s does not support variants", p.Architecture)
	}

	return nil
}
