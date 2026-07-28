package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseTTL parses human-readable duration strings like "30s", "15m", "2h", "1d" (or "24h"), or raw integer seconds ("3600").
func ParseTTL(input string) (time.Duration, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return 0, nil
	}

	// Handle day suffix "d" (e.g. 1d -> 24h, 7d -> 168h)
	if strings.HasSuffix(input, "d") || strings.HasSuffix(input, "D") {
		daysStr := input[:len(input)-1]
		days, err := strconv.Atoi(daysStr)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid day duration %q", input)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	// Try parsing standard Go duration (e.g. 30s, 15m, 2h)
	if d, err := time.ParseDuration(input); err == nil {
		if d < 0 {
			return 0, fmt.Errorf("duration cannot be negative: %q", input)
		}
		return d, nil
	}

	// Try parsing raw integer seconds (e.g. "3600")
	if seconds, err := strconv.Atoi(input); err == nil {
		if seconds < 0 {
			return 0, fmt.Errorf("duration cannot be negative: %q", input)
		}
		return time.Duration(seconds) * time.Second, nil
	}

	return 0, fmt.Errorf("invalid duration format %q (examples: 30s, 15m, 2h, 1d)", input)
}
