"""Constants for the Eon Next integration."""

DOMAIN = "eon_next"
INTEGRATION_VERSION = "1.10.0.1"  # x-release-please-version

# Authentication
CONF_EMAIL = "email"
CONF_PASSWORD = "password"  # legacy; Kraken no longer accepts it
CONF_REFRESH_TOKEN = "refresh_token"

# E.ON Next login moved to Auth0.  This is the web dashboard's public SPA
# client (served in eonnext.com's JS, no client secret).
AUTH0_TOKEN_URL = "https://auth.eonnext.com/oauth/token"
AUTH0_CLIENT_ID = "OrFeFacHUoXK2afczePYMLCRMXpwRxzW"

# Frontend / dashboard
CONF_SHOW_PANEL = "show_panel"
CONF_SHOW_CARD = "show_card"
DEFAULT_SHOW_PANEL = True
DEFAULT_SHOW_CARD = True
PANEL_TITLE = "EON Next"
PANEL_ICON = "mdi:lightning-bolt"
PANEL_URL = f"/api/{DOMAIN}/panel"
CARDS_URL = f"/{DOMAIN}/cards"

# Backfill
CONF_BACKFILL_ENABLED = "backfill_enabled"
CONF_BACKFILL_LOOKBACK_DAYS = "backfill_lookback_days"
CONF_BACKFILL_CHUNK_DAYS = "backfill_chunk_days"
CONF_BACKFILL_REQUESTS_PER_RUN = "backfill_requests_per_run"
CONF_BACKFILL_RUN_INTERVAL_MINUTES = "backfill_run_interval_minutes"
CONF_BACKFILL_DELAY_SECONDS = "backfill_delay_seconds"
CONF_BACKFILL_REBUILD_STATISTICS = "backfill_rebuild_statistics"
PLATFORMS = ["sensor", "binary_sensor", "event"]
DEFAULT_UPDATE_INTERVAL_MINUTES = 30
DEFAULT_BACKFILL_ENABLED = False
DEFAULT_BACKFILL_LOOKBACK_DAYS = 3650
DEFAULT_BACKFILL_CHUNK_DAYS = 1
DEFAULT_BACKFILL_REQUESTS_PER_RUN = 1
DEFAULT_BACKFILL_RUN_INTERVAL_MINUTES = 180
DEFAULT_BACKFILL_DELAY_SECONDS = 300
DEFAULT_BACKFILL_REBUILD_STATISTICS = True
API_BASE_URL = "https://api.eonnext-kraken.energy/v1"
GAS_CALORIC_VALUE = 38
GAS_VOLUME_CORRECTION = 1.02264
