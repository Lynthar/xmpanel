package middleware

import (
	"context"
	"net/http"

	"github.com/xmpanel/xmpanel/internal/i18n"
)

// localeKey is the context key for locale
type localeKey struct{}

// LocaleMiddleware detects and attaches locale to request context
func LocaleMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		locale := i18n.DetectLocale(r)
		ctx := context.WithValue(r.Context(), localeKey{}, locale)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetLocale retrieves the locale from context
func GetLocale(ctx context.Context) i18n.Locale {
	if locale, ok := ctx.Value(localeKey{}).(i18n.Locale); ok {
		return locale
	}
	return i18n.DefaultLocale
}

// T is a convenience function to translate using context locale
func T(ctx context.Context, key string) string {
	return i18n.T(GetLocale(ctx), key)
}
