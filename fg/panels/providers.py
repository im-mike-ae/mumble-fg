"""Host-agnostic and host-specific profile panel providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from django.urls import reverse

from fg.models import MumbleUser, MurmurModelLookupError
from fg.runtime import safe_list_servers, safe_pilot_registrations, split_host_port


@dataclass(frozen=True)
class MurmurPanelDescriptor:
    """Serializable profile panel descriptor used by host profile views."""

    key: str
    priority: int
    template: str
    panel_title: str
    server: Any
    account: Any
    temp_password: str | None
    username_with_slot: str | None
    display_name: str
    display_name_is_fallback: bool
    server_label: str
    server_hint: str
    server_address: str
    server_port: str
    is_mumble_admin: bool
    eligible_pilots: tuple[dict[str, Any], ...]
    show_pilot_selector: bool
    password_reset_url: str
    password_set_url: str
    # ShitSpeak cluster panels carry the regional connect endpoints
    # (fg.runtime.Endpoint items) for a single shared registration; empty for
    # Murmur (per-server) panels.
    endpoints: tuple = ()

    def to_panel_context(self) -> dict[str, Any]:
        return {
            'key': self.key,
            'priority': self.priority,
            'template': self.template,
            'panel_title': self.panel_title,
            'server': self.server,
            'account': self.account,
            'temp_password': self.temp_password,
            'username_with_slot': self.username_with_slot,
            'display_name': self.display_name,
            'display_name_is_fallback': self.display_name_is_fallback,
            'server_label': self.server_label,
            'server_hint': self.server_hint,
            'server_address': self.server_address,
            'server_port': self.server_port,
            'is_mumble_admin': self.is_mumble_admin,
            'eligible_pilots': list(self.eligible_pilots),
            'show_pilot_selector': self.show_pilot_selector,
            'password_reset_url': self.password_reset_url,
            'password_set_url': self.password_set_url,
            'endpoints': [
                {'host': e.host, 'port': e.port, 'label': e.label or e.host}
                for e in self.endpoints
            ],
        }


class ProfilePanelProvider(ABC):
    """Contract for host-specific panel providers."""

    provider_name = 'generic'
    panel_priority = 300
    panel_template = 'fg/panels/profile_panel.html'
    panel_title = 'MUMBLE'

    @abstractmethod
    def build_panels(self, request) -> list[dict[str, Any]]:
        """Return profile panel descriptors for the host app."""


class GenericProfilePanelProvider(ProfilePanelProvider):
    """Default profile panel provider usable by any host."""

    provider_name = 'generic'
    default_server_port = '64738'
    # ShitSpeak servers render as their own card. Key stays under a '/comms'
    # opt-in prefix ('mumble-') so the dashboard still surfaces it.
    shitspeak_panel_key_prefix = 'mumble-beta-server-'
    shitspeak_panel_template = 'fg/panels/shitspeak_panel.html'
    shitspeak_panel_title = 'SHITSPEAK'

    @staticmethod
    def _eligible_pilots(user) -> list[dict[str, Any]]:
        from fg.views import profile_password_pilot_choices

        return profile_password_pilot_choices(user)

    def _active_servers(self):
        return safe_list_servers()

    def _accounts_by_server(self, user_id: int) -> dict[int, Any]:
        try:
            # is_temporary=False ensures a guest temp row linked to this
            # user_id (e.g., from past data corruption) never surfaces as
            # the pilot's profile. order_by makes row selection deterministic
            # when more than one row matches (last-write wins).
            local: dict[int, Any] = {}
            for mumble_user in (
                MumbleUser.objects.filter(user_id=user_id, is_temporary=False)
                .select_related('server')
                .order_by('server_id', '-pk')
            ):
                local.setdefault(mumble_user.server_id, mumble_user)
            if local:
                return local
        except MurmurModelLookupError:
            pass
        return {
            registration.server_id: registration
            for registration in safe_pilot_registrations(user_id, servers=self._active_servers())
        }

    @staticmethod
    def _server_label(server) -> str:
        return str(getattr(server, 'name', '') or '').strip() or str(getattr(server, 'address', '') or '').strip() or f'server-{server.pk}'

    @staticmethod
    def _server_hint(server) -> str:
        explicit_name = str(getattr(server, 'name', '') or '').strip()
        if explicit_name:
            return explicit_name
        return str(getattr(server, 'address', '') or '').strip()

    @staticmethod
    def _server_address_port(server) -> tuple[str, str]:
        if server is None:
            return '', ''
        return split_host_port(
            getattr(server, 'address', ''),
            default_port=GenericProfilePanelProvider.default_server_port,
        )

    def _panel_descriptor(
        self,
        *,
        request,
        server,
        account,
        eligible_pilots: list[dict[str, Any]],
        key_prefix: str = 'murmur-server-',
        template: str | None = None,
        title: str | None = None,
        endpoints: tuple[str, ...] = (),
    ) -> MurmurPanelDescriptor:
        display_name, display_name_is_fallback = self._display_name(
            request.user,
            account=account,
            eligible_pilots=eligible_pilots,
        )
        username_with_slot = None
        if account is not None:
            username = str(getattr(account, 'username', '') or '').strip()
            if username:
                username_with_slot = username
        if not username_with_slot:
            username_with_slot = display_name or None
        if not username_with_slot and eligible_pilots:
            username_with_slot = str(eligible_pilots[0].get('character_name') or '').strip() or None
        server_address, server_port = self._server_address_port(server)

        return MurmurPanelDescriptor(
            key=f'{key_prefix}{getattr(server, "pk", "profile")}',
            priority=self.panel_priority,
            template=template or self.panel_template,
            panel_title=title or self.panel_title,
            server=server,
            account=account,
            temp_password=request.session.pop('murmur_temp_password', None),
            username_with_slot=username_with_slot,
            display_name=display_name,
            display_name_is_fallback=display_name_is_fallback,
            server_label=self._server_label(server) if server is not None else 'Mumble Authentication',
            server_hint=self._server_hint(server) if server is not None else 'Profile password panel',
            server_address=server_address,
            server_port=server_port,
            is_mumble_admin=bool(getattr(account, 'is_mumble_admin', False)),
            eligible_pilots=tuple(eligible_pilots),
            show_pilot_selector=len(eligible_pilots) > 1,
            password_reset_url=reverse('mumble:profile_reset_password'),
            password_set_url=reverse('mumble:profile_set_password'),
            endpoints=endpoints,
        )

    @staticmethod
    def _is_address_like(value: str) -> bool:
        """True for bare "host:port" / dotted-hostname strings.

        BG's ``name`` is often just the connection string. That is an address,
        not a display name: it already appears in the card body's Server row and
        reads badly as a heading, so it should not win over the driver default.
        """
        candidate = str(value or '').strip()
        if not candidate or ' ' in candidate:
            return False
        host = candidate
        if candidate.count(':') == 1:
            head, _, tail = candidate.rpartition(':')
            if tail.isdigit():
                return True
            host = head or candidate
        return '.' in host

    @classmethod
    def default_panel_title_for(cls, server) -> str:
        """Built-in heading for a server, before any admin label."""
        if getattr(server, 'is_shitspeak', False):
            return cls.shitspeak_panel_title
        return cls.panel_title

    @classmethod
    def panel_title_for(cls, server, panel_settings=None) -> str:
        """Tile heading: admin label, else a real BG server name, else the default.

        Also used by the admin Servers tab to preview what a tile will read.
        """
        label = str(getattr(panel_settings, 'label', '') or '').strip()
        if label:
            return label
        name = str(getattr(server, 'name', '') or '').strip()
        if name and not cls._is_address_like(name):
            return name
        return cls.default_panel_title_for(server)

    @staticmethod
    def _visible_servers(servers: list, settings_by_key: dict[str, Any]) -> list:
        """Drop servers BG marked inactive and servers an admin hid.

        A server with no ServerPanelSettings row is visible, so new BG servers
        surface without admin action.
        """
        visible = []
        for server in servers:
            if not getattr(server, 'is_active', True):
                continue
            row = settings_by_key.get(str(getattr(server, 'server_key', '') or '').strip())
            if row is not None and not row.enabled:
                continue
            visible.append(server)
        return visible

    @staticmethod
    def _panel_settings_by_key(servers: list) -> dict[str, Any]:
        """Tile settings for these servers; empty (all defaults) if unavailable."""
        from fg.models import ServerPanelSettings

        try:
            return ServerPanelSettings.by_server_key(
                getattr(server, 'server_key', '') for server in servers
            )
        except Exception:  # noqa: BLE001 - never let a settings read break the profile page
            return {}

    @staticmethod
    def _display_name(user, *, account, eligible_pilots: list[dict[str, Any]]) -> tuple[str, bool]:
        stored = str(getattr(account, 'display_name', '') or '').strip()
        if stored:
            return stored, False

        try:
            from fg.views import _compute_display_name

            computed = str(_compute_display_name(user) or '').strip()
            if computed:
                return computed, False
        except Exception:  # noqa: BLE001
            pass

        if eligible_pilots:
            return str(eligible_pilots[0].get('character_name') or ''), True
        return '', True

    def build_panels(self, request) -> list[dict[str, Any]]:
        eligible_pilots = self._eligible_pilots(request.user)
        if not eligible_pilots:
            return []

        servers = self._active_servers()
        if not servers:
            return [
                self._panel_descriptor(
                    request=request,
                    server=None,
                    account=None,
                    eligible_pilots=eligible_pilots,
                ).to_panel_context()
            ]

        settings_by_key = self._panel_settings_by_key(servers)
        servers = self._visible_servers(servers, settings_by_key)
        if not servers:
            # Every server is hidden (BG-inactive or admin-disabled). Show
            # nothing rather than the no-BG fallback card — the tiles were
            # deliberately turned off.
            return []

        target_user_id = request.user.id
        try:
            from fg.views import _resolve_bg_pkid_for_mockui

            if eligible_pilots:
                primary_character_id = str(eligible_pilots[0].get('character_id') or '')
                mapped_pkid = _resolve_bg_pkid_for_mockui(request.user, primary_character_id)
                if mapped_pkid is not None:
                    target_user_id = int(mapped_pkid)
        except Exception:  # noqa: BLE001
            # Fall back to host user id when mock-only mapping is unavailable.
            target_user_id = request.user.id

        accounts_by_server = self._accounts_by_server(target_user_id)
        descriptors: list[MurmurPanelDescriptor] = []
        for server in servers:
            account = accounts_by_server.get(server.pk)
            panel_settings = settings_by_key.get(
                str(getattr(server, 'server_key', '') or '').strip()
            )
            if getattr(server, 'is_shitspeak', False):
                # ShitSpeak is a different stack: its own card, one shared
                # registration, and a region selector over the cluster endpoints.
                endpoints = tuple(getattr(server, 'endpoints', ()) or ())
                if not endpoints and getattr(server, 'address', ''):
                    from fg.runtime import _normalize_endpoint
                    fallback = _normalize_endpoint(server.address)
                    endpoints = (fallback,) if fallback else ()
                descriptors.append(
                    self._panel_descriptor(
                        request=request,
                        server=server,
                        account=account,
                        eligible_pilots=eligible_pilots,
                        key_prefix=self.shitspeak_panel_key_prefix,
                        template=self.shitspeak_panel_template,
                        title=self.panel_title_for(server, panel_settings),
                        endpoints=endpoints,
                    )
                )
            else:
                descriptors.append(
                    self._panel_descriptor(
                        request=request,
                        server=server,
                        account=account,
                        eligible_pilots=eligible_pilots,
                        title=self.panel_title_for(server, panel_settings),
                    )
                )

        return [descriptor.to_panel_context() for descriptor in descriptors]


class CubeProfilePanelProvider(GenericProfilePanelProvider):
    """Cube adapter: currently uses generic behavior with dedicated identity."""

    provider_name = 'cube'


class AllianceAuthProfilePanelProvider(GenericProfilePanelProvider):
    """AllianceAuth adapter: currently uses generic behavior with dedicated identity."""

    provider_name = 'allianceauth'
