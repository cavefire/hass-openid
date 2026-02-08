"""User management helpers for OpenID Connect integration."""
from __future__ import annotations

import logging

from homeassistant.auth.models import User
from homeassistant.components.person import DOMAIN as PERSON_DOMAIN, async_create_person
from homeassistant.core import HomeAssistant
from homeassistant.util import slugify

_LOGGER = logging.getLogger(__name__)


async def async_ensure_person_for_user(
    hass: HomeAssistant, user: User, credential_data: dict
) -> None:
    """Create a person entry for the user if needed."""
    if PERSON_DOMAIN not in hass.data:
        _LOGGER.debug("Person component not loaded; skipping person creation")
        return

    _, storage_collection, _ = hass.data[PERSON_DOMAIN]
    items = storage_collection.async_items()

    if any(item.get("user_id") == user.id for item in items):
        return

    candidate_name = (
        credential_data.get("name")
        or credential_data.get("preferred_username")
        or credential_data.get("username")
        or user.name
    )

    if candidate_name:
        slug_candidate = slugify(candidate_name)
        for item in items:
            item_name = item.get("name")
            item_id = item.get("id")
            if (
                isinstance(item_name, str)
                and item_name.lower() == candidate_name.lower()
            ) or (
                slug_candidate
                and isinstance(item_id, str)
                and item_id == slug_candidate
            ):
                if item.get("user_id") != user.id:
                    await storage_collection.async_update_item(
                        item["id"],
                        {"user_id": user.id},
                    )
                return

    person_name = candidate_name or user.id

    try:
        await async_create_person(hass, person_name, user_id=user.id)
    except ValueError as err:
        _LOGGER.warning("Unable to create person for user %s: %s", user.id, err)


async def async_find_user_by_username(hass: HomeAssistant, username: str) -> User | None:
    """Return existing user matching username if available."""
    username_lower = username.lower()
    for candidate in await hass.auth.async_get_users():
        if candidate.name and candidate.name.lower() == username_lower:
            return candidate

        for existing_credentials in candidate.credentials:
            stored_username = existing_credentials.data.get("username")
            if (
                isinstance(stored_username, str)
                and stored_username.lower() == username_lower
            ):
                return candidate

    return None
