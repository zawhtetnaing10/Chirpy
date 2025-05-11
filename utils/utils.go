package utils

import (
	"time"
)

// Refresh token duration is 60 days
func GetRefreshTokenDuration() time.Duration {
	return 60 * 24 * time.Hour
}

// JWT Token expire time is 1 hour
func GetJWTTokenExpireTime() time.Duration {
	return 1 * time.Hour
}
