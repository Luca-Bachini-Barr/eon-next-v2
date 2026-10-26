#!/usr/bin/env python3

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from zoneinfo import ZoneInfo

import aiohttp

from .const import (
    API_BASE_URL,
    AUTH0_CLIENT_ID,
    AUTH0_TOKEN_URL,
    GAS_CALORIC_VALUE,
    GAS_VOLUME_CORRECTION,
)

_LOGGER = logging.getLogger(__name__)

METER_TYPE_GAS = "gas"
METER_TYPE_ELECTRIC = "electricity"
METER_TYPE_UNKNOWN = "unknown"


GET_ACCOUNT_DEVICES_QUERY = """
query getAccountDevices($accountNumber: String!) {
  devices(accountNumber: $accountNumber) {
    id
    provider
    deviceType
    status {
      current
    }
    __typename
    ... on SmartFlexVehicle {
      make
      model
    }
    ... on SmartFlexChargePoint {
      make
      model
    }
  }
}
"""

GET_SMART_CHARGING_SCHEDULE_QUERY = """
query getSmartChargingSchedule($deviceId: String!) {
  flexPlannedDispatches(deviceId: $deviceId) {
    start
    end
    type
    energyAddedKwh
  }
}
"""

GET_ACCOUNT_AGREEMENTS_QUERY = """
query getAccountAgreements($accountNumber: String!) {
  properties(accountNumber: $accountNumber) {
    electricityMeterPoints {
      mpan
      agreements {
        id
        validFrom
        validTo
        tariff {
          __typename
          ... on TariffType {
            displayName
            fullName
            tariffCode
          }
          ... on StandardTariff {
            unitRate
            standingCharge
          }
          ... on PrepayTariff {
            unitRate
            standingCharge
          }
          ... on HalfHourlyTariff {
            unitRates {
              value
              validFrom
              validTo
            }
            standingCharge
          }
        }
      }
    }
    gasMeterPoints {
      mprn
      agreements {
        id
        validFrom
        validTo
        tariff {
          __typename
          ... on TariffType {
            displayName
            fullName
            tariffCode
          }
          ... on GasTariffType {
            unitRate
            standingCharge
          }
        }
      }
    }
  }
}
"""


# Treat the access token as expired this many seconds before its real
# expiry, so a token is proactively refreshed rather than sent moments
# before it lapses (or being rejected under mild server clock skew).
_TOKEN_EXPIRY_MARGIN_SECONDS = 60

# Auth0 errors meaning the refresh token itself is dead - the user must paste
# a new one.
_AUTH0_FATAL_ERRORS = {"invalid_grant", "unauthorized_client", "access_denied"}


def _jwt_expiry(token: str) -> int | None:
    """Return a JWT's ``exp`` claim without verifying it, or ``None``."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp")
    except (IndexError, ValueError, AttributeError):
        return None
    return int(exp) if isinstance(exp, int | float) else None


# GraphQL consumption (replaces the REST endpoint, which rejects Auth0 tokens).
# POINTS_FIELD is swapped for electricityMeterPoints / gasMeterPoints.
_METER_CONSUMPTION_QUERY = """
query getMeterConsumption($accountNumber: String!, $startAt: DateTime!, $grouping: ConsumptionGroupings!, $timezone: String!, $first: Int!, $after: String) {
  properties(accountNumber: $accountNumber) {
    POINTS_FIELD {
      meters(includeInactive: false) {
        serialNumber
        consumptionUnits
        consumption(startAt: $startAt, grouping: $grouping, timezone: $timezone, first: $first, after: $after) {
          pageInfo {
            hasNextPage
            endCursor
          }
          edges {
            node {
              value
              startAt
              endAt
            }
          }
        }
      }
    }
  }
}
"""
_CONSUMPTION_GROUPINGS = {"half_hour": "HALF_HOUR", "hour": "HOUR", "day": "DAY"}
_CONSUMPTION_SLOT = {
    "HALF_HOUR": datetime.timedelta(minutes=30),
    "HOUR": datetime.timedelta(hours=1),
}
_CONSUMPTION_TIMEZONE = "Europe/London"
_CONSUMPTION_PAGE_SIZE = 100


def _parse_iso_datetime(value: Any) -> datetime.datetime | None:
    """Parse an ISO datetime (``Z`` allowed) to an aware datetime, or ``None``."""
    if not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def _iso_date(value: Any) -> datetime.date | None:
    """Parse the calendar-date portion of an ISO date/datetime string."""
    if not value:
        return None
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


class EonNextAuthError(Exception):
    """Raised when authentication fails."""


class EonNextApiError(Exception):
    """Raised when an API call fails."""


@dataclass(slots=True)
class SmartChargingDevice:
    """Smart charging device metadata."""

    device_id: str
    serial: str


class EonNext:
    """API client for E.ON Next.

    E.ON Next moved customer login to Auth0 (with a CAPTCHA), and Kraken's
    ``obtainKrakenToken`` no longer accepts an email/password.  The only
    headless route left is the refresh token from a signed-in browser session:
    it is exchanged at Auth0 for a short-lived ID token, which Kraken accepts
    as the raw ``Authorization`` header.  Auth0 rotates refresh tokens on every
    exchange, so each new one is handed to the token update callback to persist.
    """

    def __init__(self):
        self.username = ""
        self._session: aiohttp.ClientSession | None = None
        self._auth_lock = asyncio.Lock()
        self._on_token_update: Callable[[str], None] | None = None
        self.__reset_authentication()
        self.__reset_accounts()

    def set_token_update_callback(
        self, callback: Callable[[str], None] | None
    ) -> None:
        """Register a callback for refresh token updates."""
        self._on_token_update = callback

    def _json_contains_key_chain(self, data: Any, key_chain: list[str]) -> bool:
        for key in key_chain:
            if not isinstance(data, dict) or key not in data:
                return False
            data = data[key]
        return True

    @staticmethod
    def _has_auth_error(errors: Any) -> bool:
        if not isinstance(errors, list):
            return False

        for error in errors:
            if not isinstance(error, dict):
                continue

            message = str(error.get("message", "")).lower()
            code = str(error.get("extensions", {}).get("code", "")).lower()
            if (
                "authentication" in message
                or "authenticated" in message
                or "unauthor" in message
                or "jwt" in message
                or "unauthenticated" in code
                or "invalid_token" in code
            ):
                return True
        return False

    def __current_timestamp(self) -> int:
        return int(datetime.datetime.now().timestamp())

    def __reset_authentication(self):
        self.auth = {
            "issued": None,
            "token": {"token": None, "expires": None},
            "refresh": {"token": None, "expires": None},
        }

    def __store_authentication(self, auth0_token: dict, refresh_token: str):
        # Validate the token shape up front: a missing/renamed field must
        # surface as an auth error (→ re-auth) rather than a raw
        # KeyError/TypeError escaping the login methods.
        id_token = auth0_token.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise EonNextAuthError("Malformed authentication token payload")
        expires = _jwt_expiry(id_token)
        if expires is None:
            expires_in = auth0_token.get("expires_in")
            if not isinstance(expires_in, int | float):
                raise EonNextAuthError("Malformed authentication token payload")
            expires = self.__current_timestamp() + int(expires_in)

        # Auth0 rotates refresh tokens: the old one stops working once the
        # new one is issued, so it must be persisted immediately.
        new_refresh_token = auth0_token.get("refresh_token") or refresh_token

        self.auth = {
            "issued": self.__current_timestamp(),
            "token": {
                "token": id_token,
                "expires": expires,
            },
            # Auth0 does not report the refresh token's lifetime; it is
            # treated as valid until Auth0 rejects it.
            "refresh": {
                "token": new_refresh_token,
                "expires": None,
            },
        }
        if self._on_token_update is not None:
            try:
                self._on_token_update(new_refresh_token)
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Error while running token update callback")

    def __auth_token_is_valid(self) -> bool:
        if self.auth["token"]["token"] is None:
            return False
        token_expires = self.auth["token"]["expires"]
        if token_expires is None or not isinstance(token_expires, int | float):
            return False
        if token_expires <= self.__current_timestamp() + _TOKEN_EXPIRY_MARGIN_SECONDS:
            return False
        return True

    def __refresh_token_is_valid(self) -> bool:
        if self.auth["refresh"]["token"] is None:
            return False
        refresh_expires = self.auth["refresh"]["expires"]
        if refresh_expires is None:
            return True
        if not isinstance(refresh_expires, int | float):
            return False
        if refresh_expires <= self.__current_timestamp():
            return False
        return True

    async def __auth_token(self) -> str:
        async with self._auth_lock:
            if not self.__auth_token_is_valid():
                if self.__refresh_token_is_valid():
                    await self.__login_with_refresh_token()

            if not self.__auth_token_is_valid():
                raise EonNextAuthError("Unable to authenticate")

            return self.auth["token"]["token"]

    async def _force_token_refresh(self) -> bool:
        """Force a new access token after a server 401, ignoring the cache.

        The cached access token can look valid locally yet be rejected by the
        server (mild clock skew, or expiry between issue and arrival).  This
        invalidates it and refreshes once under the auth lock so a single 401
        is retried transparently rather than escalating to a re-auth prompt.
        Returns ``True`` if a valid token was obtained.
        """
        async with self._auth_lock:
            # Drop the cached access token so the refresh cannot short-circuit.
            self.auth["token"]["token"] = None
            self.auth["token"]["expires"] = None
            if self.__refresh_token_is_valid():
                await self.__login_with_refresh_token()
            return self.__auth_token_is_valid()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self._session

    async def async_close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _graphql_post(
        self,
        operation: str,
        query: str,
        variables: dict | None = None,
        authenticated: bool = True,
    ) -> dict:
        if variables is None:
            variables = {}

        # Authenticated calls get one transparent refresh-and-retry on a 401/403
        # (or auth-shaped GraphQL error) before escalating to re-auth.
        attempted_refresh = False
        while True:
            headers: dict[str, str] = {}
            if authenticated:
                headers["authorization"] = await self.__auth_token()

            session = await self._get_session()
            try:
                async with session.post(
                    f"{API_BASE_URL}/graphql/",
                    json={"operationName": operation, "variables": variables, "query": query},
                    headers=headers,
                ) as response:
                    if authenticated and response.status in (401, 403):
                        if not attempted_refresh:
                            attempted_refresh = True
                            if await self._force_token_refresh():
                                continue
                        raise EonNextAuthError("Authentication rejected by API")

                    try:
                        result = await response.json(content_type=None)
                    except aiohttp.ContentTypeError as err:
                        text = await response.text()
                        _LOGGER.debug(
                            "Non-JSON response for %s (status %s): %s",
                            operation,
                            response.status,
                            text[:500],
                        )
                        raise EonNextApiError("Invalid API response") from err

                    # A CDN/proxy error page can be valid JSON that is a list or
                    # null rather than the expected object; treat anything else
                    # as a transport error instead of letting ``.get`` raise
                    # ``AttributeError`` outside the client's error taxonomy.
                    if not isinstance(result, dict):
                        _LOGGER.debug(
                            "Unexpected non-object GraphQL body for %s (status %s)",
                            operation,
                            response.status,
                        )
                        raise EonNextApiError("Invalid API response")

                    if self._has_auth_error(result.get("errors")):
                        if authenticated and not attempted_refresh:
                            attempted_refresh = True
                            if await self._force_token_refresh():
                                continue
                        raise EonNextAuthError("Authentication failed")

                    errors = result.get("errors")
                    if errors and isinstance(errors, list):
                        _LOGGER.warning(
                            "GraphQL errors in %s response: %s",
                            operation,
                            [e.get("message", str(e)) for e in errors if isinstance(e, dict)],
                        )

                    return result

            except aiohttp.ClientError as err:
                _LOGGER.error("GraphQL request failed for %s: %s", operation, err)
                raise EonNextApiError(f"API request failed: {err}") from err

    async def _auth0_token_request(self, refresh_token: str) -> tuple[int, Any]:
        """Exchange an Auth0 refresh token; returns ``(status, json body)``."""
        session = await self._get_session()
        try:
            async with session.post(
                AUTH0_TOKEN_URL,
                json={
                    "grant_type": "refresh_token",
                    "client_id": AUTH0_CLIENT_ID,
                    "refresh_token": refresh_token,
                },
            ) as response:
                try:
                    body = await response.json(content_type=None)
                except (aiohttp.ContentTypeError, ValueError):
                    body = None
                return response.status, body
        except aiohttp.ClientError as err:
            raise EonNextApiError(f"Auth0 token request failed: {err}") from err

    async def login_with_refresh_token(self, token: str) -> bool:
        return await self.__login_with_refresh_token(True, token)

    async def __login_with_refresh_token(
        self,
        initialise: bool = False,
        token: str | None = None,
    ) -> bool:
        refresh_token = token or self.auth["refresh"]["token"]
        if refresh_token is None:
            return False

        # Transport errors propagate as EonNextApiError without destroying the
        # refresh token, so it can be retried once the API recovers.
        status, body = await self._auth0_token_request(refresh_token)
        error = body.get("error") if isinstance(body, dict) else None

        if status == 200 and isinstance(body, dict):
            self.__store_authentication(body, refresh_token)
            if initialise:
                await self.__init_accounts()
            return True

        if error in _AUTH0_FATAL_ERRORS or status in (400, 401, 403):
            _LOGGER.error(
                "E.ON Next refresh token was rejected (%s); a new one is needed",
                error or f"HTTP {status}",
            )
            self.__reset_authentication()
            return False

        raise EonNextApiError(f"Auth0 token refresh failed (HTTP {status})")

    def __reset_accounts(self):
        self.accounts: list[EnergyAccount] = []

    async def __get_account_info(self) -> list[dict[str, Any]]:
        """Fetch account numbers and balances from the logged-in user query.

        Returns a list of dicts with ``number`` and ``balance`` keys.
        """
        result = await self._graphql_post(
            "headerGetLoggedInUser",
            "query headerGetLoggedInUser {\n  viewer {\n    accounts {\n      ... on AccountType {\n        applications(first: 1) {\n          edges {\n            node {\n              isMigrated\n              migrationSource\n              __typename\n            }\n            __typename\n          }\n          __typename\n        }\n        balance\n        id\n        number\n        __typename\n      }\n      __typename\n    }\n    id\n    preferredName\n    __typename\n  }\n}\n",
        )

        if not self._json_contains_key_chain(result, ["data", "viewer", "accounts"]):
            raise EonNextApiError("Unable to load energy accounts")

        found: list[dict[str, Any]] = []
        for account_entry in result["data"]["viewer"]["accounts"]:
            found.append({
                "number": account_entry["number"],
                "balance": account_entry.get("balance"),
            })

        return found

    async def __init_accounts(self):
        if len(self.accounts) != 0:
            return

        for info in await self.__get_account_info():
            account = EnergyAccount(
                self, info["number"], balance=info.get("balance")
            )
            await account._load_meters()
            await account._load_ev_chargers()
            self.accounts.append(account)

    async def async_get_account_balances(self) -> dict[str, Any]:
        """Return latest account balances keyed by account number."""
        balances: dict[str, Any] = {}
        for info in await self.__get_account_info():
            account_number = str(info.get("number") or "")
            if not account_number:
                continue
            balances[account_number] = info.get("balance")

        for account in self.accounts:
            if account.account_number in balances:
                account.balance = balances[account.account_number]

        return balances

    async def async_get_consumption(
        self,
        meter_type: str,
        supply_point_id: str,
        serial: str,
        group_by: str = "day",
        page_size: int = 10,
        period_from: str | None = None,
        period_to: str | None = None,
    ) -> dict | None:
        """Fetch consumption data for one meter.

        The REST consumption endpoint rejects the Auth0 ID token, so this reads
        the GraphQL ``consumption`` connection instead and returns it in the
        REST shape callers expect: ``{"results": [{"consumption",
        "interval_start", "interval_end"}, ...]}``, newest first, in kWh.
        Without ``period_from`` the latest ``page_size`` buckets are returned.
        """
        grouping = _CONSUMPTION_GROUPINGS.get(group_by)
        if not supply_point_id or grouping is None:
            return None
        if meter_type == METER_TYPE_ELECTRIC:
            points_field = "electricityMeterPoints"
        elif meter_type == METER_TYPE_GAS:
            points_field = "gasMeterPoints"
        else:
            return None

        account_number = next(
            (
                account.account_number
                for account in self.accounts
                for meter in account.meters
                if meter.serial == serial
            ),
            None,
        )
        if account_number is None:
            return None

        tz = ZoneInfo(_CONSUMPTION_TIMEZONE)
        period_start = _parse_iso_datetime(period_from)
        if period_start is not None:
            start_at = period_start
        elif grouping == "DAY":
            today = datetime.datetime.now(tz).date()
            start_at = datetime.datetime.combine(
                today - datetime.timedelta(days=page_size - 1),
                datetime.time.min,
                tzinfo=tz,
            )
        else:
            slot = _CONSUMPTION_SLOT[grouping]
            now = datetime.datetime.now(datetime.timezone.utc)
            start_at = now - slot * page_size
            start_at -= datetime.timedelta(
                minutes=start_at.minute % int(slot.total_seconds() // 60),
                seconds=start_at.second,
                microseconds=start_at.microsecond,
            )
        end_at = _parse_iso_datetime(period_to)

        query = _METER_CONSUMPTION_QUERY.replace("POINTS_FIELD", points_field)
        nodes: list[dict[str, Any]] = []
        units: str | None = None
        after: str | None = None
        # Cap pages so a misbehaving cursor can never loop forever.
        for _page in range(20):
            result = await self._graphql_post(
                "getMeterConsumption",
                query,
                {
                    "accountNumber": account_number,
                    "startAt": start_at.isoformat(),
                    "grouping": grouping,
                    "timezone": _CONSUMPTION_TIMEZONE,
                    "first": _CONSUMPTION_PAGE_SIZE,
                    "after": after,
                },
            )
            if not self._json_contains_key_chain(result, ["data", "properties"]):
                raise EonNextApiError(f"Unable to load consumption for meter {serial}")

            connection = None
            for prop in result["data"]["properties"] or []:
                for point in (prop or {}).get(points_field) or []:
                    for meter in (point or {}).get("meters") or []:
                        if meter and meter.get("serialNumber") == serial:
                            connection = meter.get("consumption") or {}
                            units = meter.get("consumptionUnits") or units
            if connection is None:
                return None

            nodes.extend(
                edge["node"]
                for edge in connection.get("edges") or []
                if edge and edge.get("node")
            )
            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage") or not page_info.get("endCursor"):
                break
            if period_start is None and len(nodes) >= page_size:
                break
            last_start = _parse_iso_datetime(nodes[-1].get("startAt")) if nodes else None
            if end_at is not None and last_start is not None and last_start >= end_at:
                break
            after = page_info["endCursor"]

        # Gas meters can report volume; the integration treats consumption as kWh.
        unit_text = (units or "").lower()
        is_volume = (
            meter_type == METER_TYPE_GAS
            and "m" in unit_text
            and "kwh" not in unit_text
        )

        dated: list[tuple[datetime.datetime, dict[str, Any]]] = []
        for node in nodes:
            start = _parse_iso_datetime(node.get("startAt"))
            if start is None:
                continue
            if end_at is not None and start >= end_at:
                continue
            value = node.get("value")
            try:
                consumption = float(value) if value is not None else None
            except (TypeError, ValueError):
                consumption = None
            if consumption is not None and is_volume:
                consumption = (
                    consumption * GAS_VOLUME_CORRECTION * GAS_CALORIC_VALUE / 3.6
                )
            dated.append(
                (
                    start,
                    {
                        "consumption": consumption,
                        "interval_start": node.get("startAt"),
                        "interval_end": node.get("endAt"),
                    },
                )
            )

        dated.sort(key=lambda item: item[0], reverse=True)
        results = [entry for _start, entry in dated]
        if period_start is None:
            results = results[:page_size]
        return {"results": results}

    async def async_get_smart_charging_schedule(
        self,
        device_id: str,
    ) -> list[dict[str, Any]] | None:
        """Fetch smart charging schedule for a specific EV device."""
        if not device_id:
            return None

        result = await self._graphql_post(
            "getSmartChargingSchedule",
            GET_SMART_CHARGING_SCHEDULE_QUERY,
            {"deviceId": device_id},
        )
        if not self._json_contains_key_chain(result, ["data", "flexPlannedDispatches"]):
            return None

        schedule = result["data"]["flexPlannedDispatches"]
        if isinstance(schedule, list):
            return schedule
        return None

    async def async_get_tariff_data(
        self,
        account_number: str,
    ) -> dict[str, dict[str, Any]] | None:
        """Fetch active tariff agreements for all meter points on an account.

        Returns a dict keyed by supply point ID (MPAN/MPRN) with the
        currently active tariff details for each meter point.  Agreements
        are filtered so only the one whose validity window contains today
        is returned per meter point.

        Tariff values (unit rate, standing charge) are returned as-is from
        the API - callers should interpret them as pence/kWh or pence/day.
        """
        if not account_number:
            return None

        result = await self._graphql_post(
            "getAccountAgreements",
            GET_ACCOUNT_AGREEMENTS_QUERY,
            {"accountNumber": account_number},
        )
        if not self._json_contains_key_chain(result, ["data", "properties"]):
            return None

        tariffs: dict[str, dict[str, Any]] = {}
        today = datetime.date.today().isoformat()

        for prop in result["data"]["properties"]:
            if not isinstance(prop, dict):
                continue

            for elec_point in prop.get("electricityMeterPoints", []):
                mpan = elec_point.get("mpan")
                if not mpan:
                    continue
                active = self._find_active_agreement(
                    elec_point.get("agreements", []), today
                )
                if active:
                    tariffs[mpan] = active

            for gas_point in prop.get("gasMeterPoints", []):
                mprn = gas_point.get("mprn")
                if not mprn:
                    continue
                active = self._find_active_agreement(
                    gas_point.get("agreements", []), today
                )
                if active:
                    tariffs[mprn] = active

        return tariffs or None

    @staticmethod
    def _find_active_agreement(
        agreements: list[Any],
        today_iso: str,
    ) -> dict[str, Any] | None:
        """Return the currently active agreement from a list.

        An agreement is active when ``validFrom <= today`` and either
        ``validTo`` is null/empty or ``validTo >= today``.  ``validFrom`` /
        ``validTo`` are ISO datetimes (e.g. ``2026-07-08T00:00:00+00:00``);
        they are compared as calendar dates so an agreement starting today is
        not skipped for its whole first day by a lexical string comparison.
        """
        if not isinstance(agreements, list):
            return None

        today = _iso_date(today_iso)
        if today is None:
            return None

        for agreement in agreements:
            if not isinstance(agreement, dict):
                continue

            valid_from = agreement.get("validFrom") or ""
            valid_to = agreement.get("validTo") or ""

            # Skip agreements with no known (parseable) start date.
            valid_from_date = _iso_date(valid_from)
            if valid_from_date is None:
                continue
            if valid_from_date > today:
                continue
            valid_to_date = _iso_date(valid_to)
            if valid_to_date is not None and valid_to_date < today:
                continue

            tariff = agreement.get("tariff")
            if not isinstance(tariff, dict):
                continue

            unit_rate = tariff.get("unitRate")
            unit_rates_schedule: list[dict[str, Any]] | None = None
            tariff_is_tou = False

            if unit_rate is None:
                # HalfHourlyTariff stores rates in unitRates list
                unit_rates = tariff.get("unitRates")
                if isinstance(unit_rates, list) and unit_rates:
                    float_values: list[float] = []
                    schedule_entries: list[dict[str, Any]] = []
                    for r in unit_rates:
                        if not isinstance(r, dict):
                            continue
                        val = r.get("value")
                        if val is None:
                            continue
                        try:
                            float_values.append(float(val))
                        except (TypeError, ValueError):
                            continue
                        schedule_entries.append({
                            "value": float(val),
                            "validFrom": r.get("validFrom"),
                            "validTo": r.get("validTo"),
                        })
                    if float_values:
                        unit_rate = sum(float_values) / len(float_values)
                    if schedule_entries:
                        unit_rates_schedule = schedule_entries

            # Detect time-of-use: HalfHourlyTariff typename or multiple
            # distinct rate values in the schedule.
            typename = tariff.get("__typename") or ""
            if typename == "HalfHourlyTariff":
                tariff_is_tou = True
            elif unit_rates_schedule:
                distinct = {e["value"] for e in unit_rates_schedule}
                tariff_is_tou = len(distinct) > 1

            return {
                "tariff_name": tariff.get("displayName") or tariff.get("fullName"),
                "tariff_code": tariff.get("tariffCode"),
                "tariff_type": typename,
                "unit_rate": unit_rate,
                "standing_charge": tariff.get("standingCharge"),
                "valid_from": valid_from,
                "valid_to": valid_to,
                "unit_rates_schedule": unit_rates_schedule,
                "tariff_is_tou": tariff_is_tou,
            }

        return None


class EnergyAccount:
    """Represents an energy account."""

    def __init__(
        self,
        api: EonNext,
        account_number: str,
        balance: int | None = None,
    ):
        self.api = api
        self.account_number = account_number
        self.balance = balance
        self.meters: list[EnergyMeter] = []
        self.ev_chargers: list[SmartChargingDevice] = []

    async def _load_meters(self):
        result = await self.api._graphql_post(
            "getAccountMeterSelector",
            "query getAccountMeterSelector($accountNumber: String!, $showInactive: Boolean!) {\n  properties(accountNumber: $accountNumber) {\n    ...MeterSelectorPropertyFields\n    __typename\n  }\n}\n\nfragment MeterSelectorPropertyFields on PropertyType {\n  __typename\n  electricityMeterPoints {\n    ...MeterSelectorElectricityMeterPointFields\n    __typename\n  }\n  gasMeterPoints {\n    ...MeterSelectorGasMeterPointFields\n    __typename\n  }\n  id\n  postcode\n}\n\nfragment MeterSelectorElectricityMeterPointFields on ElectricityMeterPointType {\n  __typename\n  id\n  mpan\n  meters(includeInactive: $showInactive) {\n    ...MeterSelectorElectricityMeterFields\n    __typename\n  }\n}\n\nfragment MeterSelectorElectricityMeterFields on ElectricityMeterType {\n  __typename\n  activeTo\n  id\n  registers {\n    id\n    name\n    __typename\n  }\n  serialNumber\n}\n\nfragment MeterSelectorGasMeterPointFields on GasMeterPointType {\n  __typename\n  id\n  mprn\n  meters(includeInactive: $showInactive) {\n    ...MeterSelectorGasMeterFields\n    __typename\n  }\n}\n\nfragment MeterSelectorGasMeterFields on GasMeterType {\n  __typename\n  activeTo\n  id\n  registers {\n    id\n    name\n    __typename\n  }\n  serialNumber\n}\n",
            {
                "accountNumber": self.account_number,
                "showInactive": False,
            },
        )

        if not self.api._json_contains_key_chain(result, ["data", "properties"]):
            raise EonNextApiError(
                "Unable to load energy meters for account " + self.account_number
            )

        self.meters = []
        for prop in result["data"]["properties"]:
            for electricity_point in prop["electricityMeterPoints"]:
                supply_point_id = electricity_point.get("mpan") or electricity_point.get(
                    "id",
                    "",
                )
                for meter_config in electricity_point["meters"]:
                    if self._meter_is_inactive(meter_config):
                        continue
                    is_export = self._is_export_meter(
                        supply_point_id, meter_config
                    )
                    meter = ElectricityMeter(
                        self,
                        meter_config["id"],
                        meter_config["serialNumber"],
                        supply_point_id,
                        is_export=is_export,
                    )
                    self.meters.append(meter)

            for gas_point in prop["gasMeterPoints"]:
                supply_point_id = gas_point.get("mprn") or gas_point.get("id", "")
                for meter_config in gas_point["meters"]:
                    if self._meter_is_inactive(meter_config):
                        continue
                    meter = GasMeter(
                        self,
                        meter_config["id"],
                        meter_config["serialNumber"],
                        supply_point_id,
                    )
                    self.meters.append(meter)

    @staticmethod
    def _meter_is_inactive(meter_config: dict[str, Any]) -> bool:
        """Return True when a meter's ``activeTo`` is set and already past.

        Replaced meters keep coming back from the API (with ``activeTo`` in the
        past) even though ``includeInactive`` is false, and would otherwise
        create stale entities and dashboard rows for meters that no longer
        exist.  Meters with no ``activeTo`` are current and always kept.
        """
        active_to = meter_config.get("activeTo")
        if not active_to:
            return False
        try:
            parsed = datetime.datetime.fromisoformat(
                str(active_to).replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            # Unparseable date: keep the meter rather than hide it on bad data.
            return False
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        serial = meter_config.get("serialNumber")
        is_inactive = parsed <= datetime.datetime.now(datetime.timezone.utc)
        if is_inactive:
            _LOGGER.debug(
                "Skipping inactive meter %s (activeTo=%s)", serial, active_to
            )
        return is_inactive

    async def _load_ev_chargers(self):
        """Load SmartFlex EV devices if available for the account."""
        self.ev_chargers = []
        try:
            result = await self.api._graphql_post(
                "getAccountDevices",
                GET_ACCOUNT_DEVICES_QUERY,
                {"accountNumber": self.account_number},
            )
        except (EonNextApiError, EonNextAuthError) as err:
            _LOGGER.debug("Unable to load EV devices for %s: %s", self.account_number, err)
            return

        if not self.api._json_contains_key_chain(result, ["data", "devices"]):
            return

        seen: set[str] = set()
        for device in result["data"]["devices"]:
            if not isinstance(device, dict):
                continue

            device_id = device.get("id")
            if not device_id or device_id in seen:
                continue

            status = device.get("status", {}).get("current")
            if status and status != "LIVE":
                _LOGGER.debug(
                    "Skipping account device %s due to status=%s",
                    device_id,
                    status,
                )
                continue

            device_type = str(device.get("deviceType", "")).upper()
            typename = str(device.get("__typename", ""))
            is_ev_device = (
                "SMARTFLEX" in typename.upper()
                or "SMART_FLEX" in device_type
                or "VEHICLE" in device_type
                or "CHARGE_POINT" in device_type
            )
            if not is_ev_device:
                _LOGGER.debug(
                    "Skipping non-EV account device %s (typename=%s, deviceType=%s)",
                    device_id,
                    typename or "<unknown>",
                    device_type or "<unknown>",
                )
                continue

            make = str(device.get("make") or "").strip()
            model = str(device.get("model") or "").strip()
            display_name = " ".join(part for part in [make, model] if part).strip()
            if not display_name:
                display_name = str(device.get("provider") or device_id)

            self.ev_chargers.append(
                SmartChargingDevice(device_id=device_id, serial=display_name)
            )
            seen.add(device_id)

    @staticmethod
    def _is_export_meter(mpan: str, meter_config: dict[str, Any]) -> bool:
        """Detect whether an electricity meter is an export meter.

        Detection relies on register names: export meters have registers with
        "export" in the name.  (A profile-class check on the MPAN is not
        possible here - the API returns the 13-digit MPAN core, not the full
        top-line that carries the profile class.)
        """
        del mpan  # unused - kept for call-site symmetry / future top-line data

        # Register name check
        registers = meter_config.get("registers")
        if isinstance(registers, list):
            for reg in registers:
                if not isinstance(reg, dict):
                    continue
                name = str(reg.get("name") or "").lower()
                if "export" in name:
                    return True

        return False


class EnergyMeter:
    """Base class for meters."""

    def __init__(
        self,
        account: EnergyAccount,
        meter_id: str,
        serial: str,
        supply_point_id: str = "",
    ):
        self.account = account
        self.api = account.api

        self.type = METER_TYPE_UNKNOWN
        self.meter_id = meter_id
        self.serial = serial
        self.supply_point_id = supply_point_id

        self.latest_reading = None
        self.latest_reading_date = None

    def get_type(self) -> str:
        return self.type

    def get_serial(self) -> str:
        return self.serial

    def _convert_datetime_str_to_date(self, datetime_str: Any) -> datetime.date | None:
        try:
            return datetime.date.fromisoformat(str(datetime_str).split("T", 1)[0])
        except ValueError as err:
            _LOGGER.debug(
                "Unable to parse reading date for meter %s from value %r: %s",
                self.serial,
                datetime_str,
                err,
            )
            return None

    def _apply_latest_reading(self, edges: list[dict[str, Any]]) -> None:
        """Set latest_reading/date from the newest reading edge, if any.

        Preserves decimal precision (register reads can be fractional - e.g.
        gas m³) and guards a meter with no registers so an empty list does not
        raise ``IndexError`` and abort the whole coordinator update.
        """
        if not edges:
            return
        node = edges[0].get("node") or {}
        registers = node.get("registers") or []
        if not registers:
            _LOGGER.debug("No registers in latest reading for meter %s", self.serial)
            return
        try:
            self.latest_reading = float(registers[0]["value"])
        except (TypeError, ValueError, KeyError):
            _LOGGER.debug("Unparseable register value for meter %s", self.serial)
            return
        self.latest_reading_date = self._convert_datetime_str_to_date(
            node.get("readAt")
        )

    async def _update(self):
        pass


class ElectricityMeter(EnergyMeter):
    """Electricity meter."""

    def __init__(
        self,
        account: EnergyAccount,
        meter_id: str,
        serial: str,
        supply_point_id: str = "",
        is_export: bool = False,
    ):
        super().__init__(account, meter_id, serial, supply_point_id)
        self.type = METER_TYPE_ELECTRIC
        self.is_export = is_export

    async def _update(self):
        result = await self.api._graphql_post(
            "meterReadingsHistoryTableElectricityReadings",
            "query meterReadingsHistoryTableElectricityReadings($accountNumber: String!, $cursor: String, $meterId: String!) {\n  readings: electricityMeterReadings(\n    accountNumber: $accountNumber\n    after: $cursor\n    first: 12\n    meterId: $meterId\n  ) {\n    edges {\n      ...MeterReadingsHistoryTableElectricityMeterReadingConnectionTypeEdge\n      __typename\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment MeterReadingsHistoryTableElectricityMeterReadingConnectionTypeEdge on ElectricityMeterReadingConnectionTypeEdge {\n  node {\n    id\n    readAt\n    readingSource\n    registers {\n      name\n      value\n      __typename\n    }\n    source\n    __typename\n  }\n  __typename\n}\n",
            {
                "accountNumber": self.account.account_number,
                "cursor": "",
                "meterId": self.meter_id,
            },
        )

        if not self.api._json_contains_key_chain(result, ["data", "readings"]):
            _LOGGER.warning("Unable to load readings for meter %s", self.serial)
            return

        self._apply_latest_reading(result["data"]["readings"]["edges"])


class GasMeter(EnergyMeter):
    """Gas meter."""

    def __init__(
        self,
        account: EnergyAccount,
        meter_id: str,
        serial: str,
        supply_point_id: str = "",
    ):
        super().__init__(account, meter_id, serial, supply_point_id)
        self.type = METER_TYPE_GAS

    async def _update(self):
        result = await self.api._graphql_post(
            "meterReadingsHistoryTableGasReadings",
            "query meterReadingsHistoryTableGasReadings($accountNumber: String!, $cursor: String, $meterId: String!) {\n  readings: gasMeterReadings(\n    accountNumber: $accountNumber\n    after: $cursor\n    first: 12\n    meterId: $meterId\n  ) {\n    edges {\n      ...MeterReadingsHistoryTableGasMeterReadingConnectionTypeEdge\n      __typename\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment MeterReadingsHistoryTableGasMeterReadingConnectionTypeEdge on GasMeterReadingConnectionTypeEdge {\n  node {\n    id\n    readAt\n    readingSource\n    registers {\n      name\n      value\n      __typename\n    }\n    source\n    __typename\n  }\n  __typename\n}\n",
            {
                "accountNumber": self.account.account_number,
                "cursor": "",
                "meterId": self.meter_id,
            },
        )

        if not self.api._json_contains_key_chain(result, ["data", "readings"]):
            _LOGGER.warning("Unable to load readings for meter %s", self.serial)
            return

        self._apply_latest_reading(result["data"]["readings"]["edges"])

    def get_latest_reading_kwh(self, m3_value: float) -> float:
        """Convert gas m3 reading to kWh."""
        from .const import GAS_CALORIC_VALUE, GAS_VOLUME_CORRECTION

        kwh = m3_value * GAS_VOLUME_CORRECTION
        kwh = kwh * GAS_CALORIC_VALUE
        kwh = kwh / 3.6
        # Keep sub-kWh precision (whole-kWh rounding loses real consumption on
        # small deltas).  Calorific value is a fixed approximation (38) - real
        # per-period values vary and would need a dedicated API source.
        return round(kwh, 3)
