"""Config flow to configure Eon Next."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback
import homeassistant.helpers.config_validation as cv

from .const import (
    CONF_BACKFILL_CHUNK_DAYS,
    CONF_BACKFILL_DELAY_SECONDS,
    CONF_BACKFILL_ENABLED,
    CONF_BACKFILL_LOOKBACK_DAYS,
    CONF_BACKFILL_REBUILD_STATISTICS,
    CONF_BACKFILL_REQUESTS_PER_RUN,
    CONF_BACKFILL_RUN_INTERVAL_MINUTES,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_SHOW_CARD,
    CONF_SHOW_PANEL,
    DEFAULT_BACKFILL_CHUNK_DAYS,
    DEFAULT_BACKFILL_DELAY_SECONDS,
    DEFAULT_BACKFILL_ENABLED,
    DEFAULT_BACKFILL_LOOKBACK_DAYS,
    DEFAULT_BACKFILL_REBUILD_STATISTICS,
    DEFAULT_BACKFILL_REQUESTS_PER_RUN,
    DEFAULT_BACKFILL_RUN_INTERVAL_MINUTES,
    DEFAULT_SHOW_CARD,
    DEFAULT_SHOW_PANEL,
    DOMAIN,
)
from .eonnext import EonNext, EonNextApiError, EonNextAuthError

_LOGGER = logging.getLogger(__name__)


class EonNextConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle Eon Next config flow."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> EonNextOptionsFlow:
        """Return options flow for this handler."""
        return EonNextOptionsFlow()

    async def _validate_refresh_token(self, refresh_token: str) -> str | None:
        """Validate an Auth0 refresh token against E.ON Next.

        Auth0 rotates the token on use, so the *new* refresh token is returned
        on success (the submitted one is dead by then), or None on failure.
        """
        api = EonNext()
        try:
            if await api.login_with_refresh_token(refresh_token.strip()):
                return api.auth["refresh"]["token"]
            return None
        except EonNextAuthError:
            return None
        except EonNextApiError as err:
            _LOGGER.debug("API/connection error during token validation: %s", err)
            raise
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected error during authentication")
            raise
        finally:
            await api.async_close()

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Invoked when a user initiates a flow via the user interface."""
        errors: dict[str, str] = {}

        if user_input is not None:
            email = user_input[CONF_EMAIL].strip().lower()

            await self.async_set_unique_id(email)
            self._abort_if_unique_id_configured()

            try:
                refresh_token = await self._validate_refresh_token(
                    user_input[CONF_REFRESH_TOKEN]
                )
            except EonNextApiError:
                errors["base"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except
                errors["base"] = "unknown"
            else:
                if refresh_token is not None:
                    return self.async_create_entry(
                        title="Eon Next",
                        data={
                            CONF_EMAIL: email,
                            CONF_REFRESH_TOKEN: refresh_token,
                        },
                    )
                errors["base"] = "invalid_auth"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): cv.string,
                    vol.Required(CONF_REFRESH_TOKEN): cv.string,
                }
            ),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]):
        """Handle initiation of re-auth flow."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ):
        """Handle confirmation of re-auth flow."""
        errors: dict[str, str] = {}

        reauth_entry = self._get_reauth_entry()

        if user_input is not None:
            try:
                refresh_token = await self._validate_refresh_token(
                    user_input[CONF_REFRESH_TOKEN]
                )
            except EonNextApiError:
                errors["base"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except
                errors["base"] = "unknown"
            else:
                if refresh_token is not None:
                    # Drop the legacy password: Kraken no longer accepts it.
                    data = {
                        k: v
                        for k, v in reauth_entry.data.items()
                        if k != CONF_PASSWORD
                    }
                    data[CONF_REFRESH_TOKEN] = refresh_token
                    return self.async_update_reload_and_abort(
                        reauth_entry,
                        data=data,
                        reason="reauth_successful",
                    )
                errors["base"] = "invalid_auth"

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_REFRESH_TOKEN): cv.string,
                }
            ),
            description_placeholders={"email": reauth_entry.data[CONF_EMAIL]},
            errors=errors,
        )


class EonNextOptionsFlow(config_entries.OptionsFlow):
    """Handle Eon Next options."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Manage Eon Next options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SHOW_PANEL,
                        default=options.get(
                            CONF_SHOW_PANEL, DEFAULT_SHOW_PANEL
                        ),
                    ): bool,
                    vol.Required(
                        CONF_SHOW_CARD,
                        default=options.get(
                            CONF_SHOW_CARD, DEFAULT_SHOW_CARD
                        ),
                    ): bool,
                    vol.Required(
                        CONF_BACKFILL_ENABLED,
                        default=options.get(
                            CONF_BACKFILL_ENABLED, DEFAULT_BACKFILL_ENABLED
                        ),
                    ): bool,
                    vol.Required(
                        CONF_BACKFILL_REBUILD_STATISTICS,
                        default=options.get(
                            CONF_BACKFILL_REBUILD_STATISTICS,
                            DEFAULT_BACKFILL_REBUILD_STATISTICS,
                        ),
                    ): bool,
                    vol.Required(
                        CONF_BACKFILL_LOOKBACK_DAYS,
                        default=options.get(
                            CONF_BACKFILL_LOOKBACK_DAYS,
                            DEFAULT_BACKFILL_LOOKBACK_DAYS,
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=36500)),
                    vol.Required(
                        CONF_BACKFILL_CHUNK_DAYS,
                        default=options.get(
                            CONF_BACKFILL_CHUNK_DAYS,
                            DEFAULT_BACKFILL_CHUNK_DAYS,
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=31)),
                    vol.Required(
                        CONF_BACKFILL_REQUESTS_PER_RUN,
                        default=options.get(
                            CONF_BACKFILL_REQUESTS_PER_RUN,
                            DEFAULT_BACKFILL_REQUESTS_PER_RUN,
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=10)),
                    vol.Required(
                        CONF_BACKFILL_RUN_INTERVAL_MINUTES,
                        default=options.get(
                            CONF_BACKFILL_RUN_INTERVAL_MINUTES,
                            DEFAULT_BACKFILL_RUN_INTERVAL_MINUTES,
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=1440)),
                    vol.Required(
                        CONF_BACKFILL_DELAY_SECONDS,
                        default=options.get(
                            CONF_BACKFILL_DELAY_SECONDS,
                            DEFAULT_BACKFILL_DELAY_SECONDS,
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=0, max=3600)),
                }
            ),
        )
