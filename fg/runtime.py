"""BG-backed runtime view models used when host Murmur ORM models are absent."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

from django.contrib.auth import get_user_model
from django.utils.dateparse import parse_datetime

from fg.control import BgControlClient, BgSyncError

logger = logging.getLogger(__name__)

DEFAULT_MUMBLE_PORT = '64738'


def split_host_port(raw_address: Any, *, default_port: str = DEFAULT_MUMBLE_PORT) -> tuple[str, str]:
    """Split a Murmur address into ``(host, port)``.

    The Mumble client's connect dialog takes the host and the port in separate
    fields and rejects a pasted ``host:port`` string, so anything we show a
    pilot has to be split before it reaches the page.
    """
    address = str(raw_address or '').strip()
    if not address:
        return '', ''
    port = ''

    if '://' in address:
        parsed = urlparse(address)
        host = str(parsed.hostname or '').strip()
        if host:
            address = host
        try:
            # A non-numeric port in the URL raises rather than returning None.
            parsed_port = parsed.port
        except ValueError:
            parsed_port = None
        if parsed_port:
            port = str(parsed_port)

    if not port and address.startswith('['):
        if ']:' in address:
            end = address.find(']')
            parsed_port = address[end + 2 :].strip()
            return address[1:end], parsed_port if parsed_port.isdigit() else default_port
        if address.endswith(']'):
            return address[1:-1].strip(), default_port

    if not port and ':' in address and address.count(':') == 1:
        host, parsed_port = address.rsplit(':', 1)
        host = str(host).strip()
        parsed_port = parsed_port.strip()
        # Anything that isn't a port number is dropped rather than left on the
        # host: a host field Mumble would reject is the bug this split exists
        # to avoid.
        return host, parsed_port if parsed_port.isdigit() else default_port

    return address, port or default_port


@dataclass(frozen=True)
class Endpoint:
    """One regional connect endpoint for a shitspeak cluster. Frozen + hashable
    so it can live on the (frozen, hashable) RuntimeServer."""
    label: str
    host: str
    port: str
    address: str


@dataclass(frozen=True)
class RuntimeServer:
    id: int
    name: str
    address: str
    server_key: str
    is_active: bool = True
    driver: str = 'ice'
    endpoints: tuple[Endpoint, ...] = field(default_factory=tuple)

    @property
    def pk(self) -> int:
        return self.id

    @property
    def is_shitspeak(self) -> bool:
        return str(self.driver or '').strip().lower() == 'shitspeak'


@dataclass
class RuntimeRegistration:
    user_id: int
    server: RuntimeServer
    username: str
    display_name: str = ''
    mumble_userid: int | None = None
    is_active: bool = True
    is_mumble_admin: bool = False
    contract_evepilot_id: int | None = None
    contract_corporation_id: int | None = None
    contract_alliance_id: int | None = None
    contract_kdf_iterations: int | None = None
    hashfn: str = ''
    active_session_ids: tuple[int, ...] = field(default_factory=tuple)
    has_priority_speaker: bool = False
    last_authenticated: Any = None
    last_connected: Any = None
    last_seen: Any = None
    last_spoke: Any = None
    user: Any = None
    groups: str = ''

    @property
    def server_id(self) -> int:
        return self.server.pk

    @property
    def pk(self) -> str:
        return f'{self.user_id}:{self.server_id}'

    @property
    def active_session_count(self) -> int:
        return len(self.active_session_ids)


def _coerce_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    return default


def _normalize_endpoint(item) -> "Endpoint | None":
    """Normalize a /v1/servers endpoint into an ``Endpoint``.

    Accepts a dict (BG that carries region labels) or a plain ``host:port``
    string (older BG). Returns None for empty items.
    """
    if isinstance(item, dict):
        host = str(item.get('host', '') or '').strip()
        port = str(item.get('port', '') or '').strip()
        address = str(item.get('address', '') or '').strip() or (f'{host}:{port}' if port else host)
        if not address:
            return None
        label = str(item.get('label', '') or '').strip() or host or address
        return Endpoint(label=label, host=host or address, port=port, address=address)
    s = str(item or '').strip()
    if not s:
        return None
    host, sep, port = s.rpartition(':')
    if sep and port.isdigit():
        return Endpoint(label=host, host=host, port=port, address=s)
    return Endpoint(label=s, host=s, port='', address=s)


def _coerce_datetime(value: Any):
    if not isinstance(value, str) or not value:
        return None
    return parse_datetime(value)


class BgRuntimeService:
    """Adapt BG control/probe payloads into view-friendly runtime objects."""

    def __init__(self, client: BgControlClient | None = None):
        self._client = client or BgControlClient()

    @staticmethod
    def _server_from_payload(payload: dict[str, Any]) -> RuntimeServer | None:
        server_id = _coerce_int(payload.get('id'))
        if server_id is None:
            return None
        server_key = str(payload.get('server_key', '') or '').strip()
        if not server_key:
            logger.warning('Skipping BG server payload without server_key: %s', payload)
            return None
        # Prefer 'endpoint_details' (dicts with region labels); fall back to the
        # older 'endpoints' (host:port strings) so deploy order doesn't matter.
        raw_endpoints = payload.get('endpoint_details')
        if not isinstance(raw_endpoints, list):
            raw_endpoints = payload.get('endpoints')
        endpoints = tuple(
            ep for ep in (
                _normalize_endpoint(item)
                for item in (raw_endpoints if isinstance(raw_endpoints, list) else [])
            ) if ep is not None
        )
        return RuntimeServer(
            id=server_id,
            name=str(payload.get('name', '') or '').strip() or f'server-{server_id}',
            address=str(payload.get('address', '') or '').strip(),
            server_key=server_key,
            is_active=_coerce_bool(payload.get('is_active'), default=True),
            driver=str(payload.get('driver', 'ice') or 'ice').strip().lower(),
            endpoints=endpoints,
        )

    @staticmethod
    def _fallback_server_from_registration(payload: dict[str, Any]) -> RuntimeServer | None:
        server_id = _coerce_int(payload.get('server_id'))
        if server_id is None:
            return None
        return RuntimeServer(
            id=server_id,
            name=str(payload.get('server_name', '') or '').strip() or f'server-{server_id}',
            address='',
            server_key='',
            is_active=_coerce_bool(payload.get('is_active'), default=True),
        )

    def list_servers(self) -> list[RuntimeServer]:
        servers: list[RuntimeServer] = []
        for payload in self._client.list_servers():
            server = self._server_from_payload(payload)
            if server is not None:
                servers.append(server)
        return servers

    def server_by_id(self, server_id: int) -> RuntimeServer | None:
        target_id = int(server_id)
        for server in self.list_servers():
            if server.pk == target_id:
                return server
        return None

    def _registration_from_payload(
        self,
        payload: dict[str, Any],
        *,
        servers_by_id: dict[int, RuntimeServer],
    ) -> RuntimeRegistration | None:
        pkid = _coerce_int(payload.get('pkid'))
        if pkid is None:
            return None
        server_id = _coerce_int(payload.get('server_id'))
        if server_id is None:
            return None
        server = servers_by_id.get(server_id) or self._fallback_server_from_registration(payload)
        if server is None:
            return None
        session_ids = tuple(
            sorted(
                session_id
                for session_id in (_coerce_int(value) for value in payload.get('active_session_ids', []))
                if session_id is not None
            )
        )
        return RuntimeRegistration(
            user_id=pkid,
            server=server,
            username=str(payload.get('username', '') or '').strip(),
            display_name=str(payload.get('display_name', '') or '').strip(),
            mumble_userid=_coerce_int(payload.get('mumble_userid')),
            is_active=_coerce_bool(payload.get('is_active'), default=True),
            is_mumble_admin=_coerce_bool(payload.get('is_murmur_admin')),
            contract_evepilot_id=_coerce_int(payload.get('evepilot_id')),
            contract_corporation_id=_coerce_int(payload.get('corporation_id')),
            contract_alliance_id=_coerce_int(payload.get('alliance_id')),
            contract_kdf_iterations=_coerce_int(payload.get('kdf_iterations')),
            hashfn=str(payload.get('hashfn', '') or ''),
            groups=str(payload.get('groups', '') or ''),
            active_session_ids=session_ids,
            has_priority_speaker=_coerce_bool(payload.get('has_priority_speaker')),
            last_authenticated=_coerce_datetime(payload.get('last_authenticated')),
            last_connected=_coerce_datetime(payload.get('last_connected')),
            last_seen=_coerce_datetime(payload.get('last_seen')),
            last_spoke=_coerce_datetime(payload.get('last_spoke')),
        )

    def registrations_for_pilot(self, pkid: int, *, servers: list[RuntimeServer] | None = None) -> list[RuntimeRegistration]:
        servers = servers if servers is not None else self.list_servers()
        servers_by_id = {server.pk: server for server in servers}
        rows = self._client.probe_pilot_registrations(pkid)
        registrations: list[RuntimeRegistration] = []
        for payload in rows:
            registration = self._registration_from_payload(payload, servers_by_id=servers_by_id)
            if registration is not None:
                registrations.append(registration)
        return registrations

    def registration_for_pilot_server(
        self,
        pkid: int,
        *,
        server_id: int,
        servers: list[RuntimeServer] | None = None,
    ) -> RuntimeRegistration | None:
        for registration in self.registrations_for_pilot(pkid, servers=servers):
            if registration.server_id == int(server_id):
                return registration
        return None

    def list_registrations(self, *, servers: list[RuntimeServer] | None = None) -> list[RuntimeRegistration]:
        servers = servers if servers is not None else self.list_servers()
        servers_by_id = {server.pk: server for server in servers}
        registrations: list[RuntimeRegistration] = []
        for payload in self._client.list_registrations():
            registration = self._registration_from_payload(payload, servers_by_id=servers_by_id)
            if registration is not None:
                registrations.append(registration)
        return registrations

    def attach_users(self, registrations: list[RuntimeRegistration]) -> list[RuntimeRegistration]:
        if not registrations:
            return registrations
        user_model = get_user_model()
        user_map = user_model.objects.in_bulk({registration.user_id for registration in registrations})
        for registration in registrations:
            registration.user = user_map.get(registration.user_id) or SimpleNamespace(
                username=f'user-{registration.user_id}'
            )
        return registrations


_RUNTIME_SERVICE = BgRuntimeService()


def get_runtime_service() -> BgRuntimeService:
    return _RUNTIME_SERVICE


def safe_list_servers() -> list[RuntimeServer]:
    try:
        return get_runtime_service().list_servers()
    except BgSyncError as exc:
        logger.warning('Failed to load BG server inventory: %s', exc)
        return []


def safe_pilot_registrations(pkid: int, *, servers: list[RuntimeServer] | None = None) -> list[RuntimeRegistration]:
    try:
        return get_runtime_service().registrations_for_pilot(pkid, servers=servers)
    except BgSyncError as exc:
        logger.warning('Failed to load BG registrations for pkid=%s: %s', pkid, exc)
        return []


def safe_registration_inventory(*, servers: list[RuntimeServer] | None = None) -> list[RuntimeRegistration]:
    try:
        return get_runtime_service().list_registrations(servers=servers)
    except BgSyncError as exc:
        logger.warning('Failed to load BG registration inventory: %s', exc)
        return []


__all__ = [
    'BgRuntimeService',
    'RuntimeRegistration',
    'RuntimeServer',
    'get_runtime_service',
    'safe_list_servers',
    'safe_pilot_registrations',
    'safe_registration_inventory',
]
