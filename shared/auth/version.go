package auth

// ValidateReleaseVersion ensures a version string is safe for URL paths and storage keys.
func ValidateReleaseVersion(version string) bool {
	if version == "" || len(version) > 64 {
		return false
	}
	for _, r := range version {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
