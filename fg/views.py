import json
import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.http import Http404, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.timezone import now
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from .eligibility import (
    DENIAL_REASON_RANK,
    account_rule_decisions,
    blocked_user_reasons,
    build_rule_sets,
    explicit_rule_match,
    all_referenced_ids,
    blocked_main_list as _common_blocked_main_list,
    eligible_account_list as _common_eligible_account_list,
)
from fgbg_common.entity_types import (
    ENTITY_TYPE_ALLIANCE,
    ENTITY_TYPE_CORPORATION,
    ENTITY_TYPE_PILOT,
)

from .acl_sync import sync_acl_rules_to_bg
from .control import BgControlClient, BgSyncError, is_handshake_failure_error
from .group_mapping import (
    all_cube_group_names,
    effective_groups_csv_for_user,
    ignored_cube_group_names,
    ignored_murmur_group_names,
    mapped_murmur_groups_for_cube_group,
    store_inventory_snapshot,
    user_has_mumble_admin_bypass,
)
from .host import get_host_adapter
from .models import (
    ACCESS_RULE_SOURCE_GROUP_GRANT,
    ACCESS_RULE_SOURCE_MANUAL,
    ACL_AUDIT_ACTION_CREATE,
    ACL_AUDIT_ACTION_DELETE,
    ACL_AUDIT_ACTION_UPDATE,
    AccessRule,
    CubeGroupMapping,
    IgnoredCubeGroup,
    IgnoredMurmurGroup,
    MumbleUser, MurmurModelLookupError, access_rule_snapshot, append_access_rule_audit,
    MurmurInventorySnapshot,
    ServerPanelSettings,
    TempLink,
    resolve_murmur_models,
)
from .runtime import (
    RuntimeRegistration,
    get_runtime_service,
    safe_list_servers,
    safe_registration_inventory,
    split_host_port,
)

logger = logging.getLogger(__name__)
_CONTROL_CLIENT = BgControlClient()

_FORBIDDEN_PASSWORD_CHARS = frozenset({" ", "'", '"', '`', '\\'})


def _password_has_supported_chars(password):
    """Validate user-provided password before sending to BG for hashing."""
    for ch in password:
        if ord(ch) < 33 or ord(ch) > 126:
            return False
        if ch in _FORBIDDEN_PASSWORD_CHARS:
            return False
    return True


def _sync_remote_registration(mumble_user, password=None):
    return _CONTROL_CLIENT.sync_murmur_registration(
        mumble_user,
        password=password,
        requested_by=str(getattr(mumble_user.user, 'username', 'unknown')),
    )


def _unregister_remote_registration(mumble_user):
    return _CONTROL_CLIENT.unregister_murmur_registration(
        mumble_user,
        requested_by=str(getattr(mumble_user.user, 'username', 'unknown')),
    )


def _sync_live_admin_membership(mumble_user):
    return _CONTROL_CLIENT.sync_live_admin_membership(
        mumble_user,
        requested_by=str(getattr(mumble_user.user, 'username', 'unknown')),
    )


def _sync_password(mumble_user, password=None):
    return _CONTROL_CLIENT.reset_murmur_password(
        mumble_user,
        password=password,
        requested_by=str(getattr(mumble_user.user, 'username', 'unknown')),
    )


def _sync_contract_metadata(
    mumble_user,
    *,
    evepilot_id,
    corporation_id,
    alliance_id,
    kdf_iterations,
    requested_by,
    is_super,
):
    return _CONTROL_CLIENT.sync_registration_contract(
        mumble_user,
        evepilot_id=evepilot_id,
        corporation_id=corporation_id,
        alliance_id=alliance_id,
        kdf_iterations=kdf_iterations,
        requested_by=requested_by,
        is_super=is_super,
    )


def _coerce_optional_int(value, *, field_name):
    if value is None:
        return None
    normalized = str(value).strip()
    if not normalized:
        return None
    try:
        return int(normalized)
    except (TypeError, ValueError) as exc:
        raise BgSyncError(f'{field_name} must be an integer') from exc


def _host_murmur_models_available() -> bool:
    try:
        resolve_murmur_models()
    except MurmurModelLookupError:
        return False
    return True


def _resolve_server(server_id):
    server = next((server for server in safe_list_servers() if server.pk == int(server_id)), None)
    if server is None or not server.is_active:
        raise Http404()
    return server


def _runtime_registration(pkid: int, *, server_id: int):
    server = next((server for server in safe_list_servers() if server.pk == int(server_id)), None)
    if server is None:
        return None
    try:
        return get_runtime_service().registration_for_pilot_server(pkid, server_id=server_id, servers=[server])
    except BgSyncError as exc:
        logger.warning(
            'Failed to load BG registration for pkid=%s server_id=%s: %s',
            pkid,
            server_id,
            exc,
        )
        return None


def _user_registration(user, *, server_id: int):
    if _host_murmur_models_available():
        local = MumbleUser.objects.filter(user=user, server_id=server_id).select_related('user', 'server').first()
        if local is not None:
            return local

    registration = _runtime_registration(user.pk, server_id=server_id)
    if registration is not None:
        registration.user = user
    return registration


def _build_registration_target(user, server, *, existing=None):
    target = RuntimeRegistration(
        user_id=user.pk,
        user=user,
        server=server,
        username=str(getattr(existing, 'username', '') or _get_mumble_username(user)),
        display_name=str(getattr(existing, 'display_name', '') or _compute_display_name(user)),
        mumble_userid=getattr(existing, 'mumble_userid', None),
        is_active=bool(getattr(existing, 'is_active', True)),
        is_mumble_admin=bool(getattr(existing, 'is_mumble_admin', False)),
        groups=str(getattr(existing, 'groups', '') or ''),
    )
    if not target.groups:
        target.groups = _compute_groups(user, mumble_user=target)
    return target


def _get_mumble_username(user):
    main = get_host_adapter().get_main_character(user)
    if main:
        return main.character_name.replace(' ', '_')
    return user.username.replace(' ', '_')


def _get_ticker(endpoint, label):
    """Fetch a ticker from ESI. Returns the ticker string or empty string on failure."""
    try:
        from modules.esi_queue.adapter import EsiQueueClient
        esi = EsiQueueClient(source='mumble')
        data = esi.make_request(endpoint)
        if data and isinstance(data, dict):
            ticker = data.get('ticker', '')
            if not ticker:
                logger.warning('ESI %s response missing ticker key: %s', label, endpoint)
            return ticker
        logger.warning('ESI %s returned unexpected data for %s: %r', label, endpoint, data)
    except Exception:
        logger.exception('Failed to fetch %s ticker from ESI endpoint %s', label, endpoint)
    return ''


def _compute_display_name(user):
    """Build display name like [ALLIANCE.CORP] Character Name."""
    main = get_host_adapter().get_main_character(user)
    if not main:
        return user.username

    char_name = main.character_name
    tags = []

    # Prefer tickers from the host database; fall back to ESI.
    alliance_ticker = getattr(main, 'alliance_ticker', '') or ''
    if not alliance_ticker and main.alliance_id:
        alliance_ticker = _get_ticker(f'/alliances/{main.alliance_id}/', 'alliance')
    if alliance_ticker:
        tags.append(alliance_ticker)

    corporation_ticker = getattr(main, 'corporation_ticker', '') or ''
    if not corporation_ticker and main.corporation_id:
        corporation_ticker = _get_ticker(f'/corporations/{main.corporation_id}/', 'corporation')
    if corporation_ticker:
        tags.append(corporation_ticker)

    if tags:
        result = f'[{" ".join(tags)}] {char_name}'
    else:
        result = char_name
    logger.debug('Computed display name for user %s: %s', user, result)
    return result


def _compute_groups(user, mumble_user=None):
    return effective_groups_csv_for_user(user, mumble_user=mumble_user)


def _push_pilot_snapshot_to_bg(user) -> bool:
    """Best-effort push of a fresh ACL + pilot snapshot to BG.

    BG can only auto-provision a Murmur registration for a pilot it already has
    in its cached snapshot. A member who registered in Cube since the last
    periodic ACL/snapshot sync isn't in that snapshot yet, so activation 404s.
    Pushing here lets activation succeed on the first click instead of waiting
    for the periodic cadence. Never raises — on failure we fall back to the
    periodic sync and the user can retry later.
    """
    try:
        sync_acl_rules_to_bg(
            requested_by=str(getattr(user, 'username', 'unknown')),
            actor_username=str(getattr(user, 'username', 'system')),
            source='activate_self_heal',
            trigger='activate',
        )
        return True
    except Exception:  # noqa: BLE001 — best-effort; activation must not hard-fail here
        logger.exception(
            'Self-heal pilot-snapshot push to BG failed for user=%s',
            getattr(user, 'pk', None),
        )
        return False


@require_POST
@login_required
def activate(request, server_id):
    server = _resolve_server(server_id)
    existing_registration = _user_registration(request.user, server_id=server.pk)
    if existing_registration is not None:
        messages.info(request, _('Murmur account already exists on this server.'))
        return redirect('profile')

    mumble_user = _build_registration_target(request.user, server)
    if _host_murmur_models_available():
        persisted_user = MumbleUser(
            user=request.user,
            server=server,
            username=mumble_user.username,
            display_name=mumble_user.display_name,
            groups=mumble_user.groups,
            pwhash='',
        )
        persisted_user.save()
        mumble_user = persisted_user
    try:
        murmur_userid = _sync_remote_registration(mumble_user)
    except BgSyncError as exc:
        # A 404 means BG has no snapshot entry for this pilot yet. Push a fresh
        # snapshot and retry once so a just-registered member can activate
        # immediately rather than waiting for the next periodic sync.
        if getattr(exc, 'code', None) == 404 and _push_pilot_snapshot_to_bg(request.user):
            try:
                murmur_userid = _sync_remote_registration(mumble_user)
            except BgSyncError as retry_exc:
                exc = retry_exc
            else:
                exc = None
        if exc is not None:
            logger.warning(
                'Failed to provision Murmur registration for MumbleUser pk=%s on server=%s: %s',
                getattr(mumble_user, 'pk', 'bg-runtime'),
                server.pk,
                exc,
            )
            messages.warning(
                request,
                _('Murmur registration sync failed. Requesting a new password later will retry it.'),
            )
            return redirect('profile')

    if _host_murmur_models_available() and mumble_user.mumble_userid != murmur_userid:
        mumble_user.mumble_userid = murmur_userid
        mumble_user.save(update_fields=['mumble_userid', 'updated_at'])

    # Request initial password from BG (BG generates it).
    try:
        password, _murmur_userid = _sync_password(mumble_user)
        request.session['murmur_temp_password'] = password
    except BgSyncError:
        logger.warning('Initial password request failed for new registration on server=%s', server.pk)
    messages.success(request, _('Murmur account created.'))
    return redirect('profile')


@require_POST
@login_required
def reset_password(request, server_id):
    mumble_user = _user_registration(request.user, server_id=server_id)
    if mumble_user is None:
        messages.error(request, _('No Murmur account found.'))
        return redirect('profile')

    try:
        password, murmur_userid = _sync_password(mumble_user)
    except BgSyncError as exc:
        logger.warning(
            'Failed to sync Murmur password reset for MumbleUser pk=%s on server=%s: %s',
            mumble_user.pk,
            mumble_user.server_id,
            exc,
        )
        messages.warning(
            request,
            _('Murmur password reset request could not complete now. Retrying later will request a new password again.'),
        )
        return redirect('profile')

    if _host_murmur_models_available() and mumble_user.mumble_userid != murmur_userid:
        mumble_user.mumble_userid = murmur_userid
        mumble_user.save(update_fields=['mumble_userid', 'updated_at'])
    messages.success(request, _('Murmur password has been reset.'))
    request.session['murmur_temp_password'] = password
    return redirect('profile')


@require_POST
@login_required
def set_password(request, server_id):
    mumble_user = _user_registration(request.user, server_id=server_id)
    if mumble_user is None:
        messages.error(request, _('No Murmur account found.'))
        return redirect('profile')

    password = request.POST.get('murmur_password', '')
    if len(password) < 8:
        messages.error(request, _('Password must be at least 8 characters.'))
        return redirect('profile')
    if not _password_has_supported_chars(password):
        messages.error(request, _("Password may not contain any of: ' \" ` \\"))
        return redirect('profile')

    try:
        resolved_password, murmur_userid = _sync_password(mumble_user, password=password)
    except BgSyncError as exc:
        logger.warning(
            'Failed to sync Murmur custom password for MumbleUser pk=%s on server=%s: %s',
            mumble_user.pk,
            mumble_user.server_id,
            exc,
        )
        messages.warning(
            request,
            _('Murmur password set request could not complete now. Retrying later will re-issue the request.'),
        )
    else:
        del resolved_password
        if _host_murmur_models_available() and mumble_user.mumble_userid != murmur_userid:
            mumble_user.mumble_userid = murmur_userid
            mumble_user.save(update_fields=['mumble_userid', 'updated_at'])
        messages.success(request, _('Murmur password updated.'))
    return redirect('profile')


def _profile_password_action_response(request):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    pilot_id_raw = str(request.POST.get('pilot_id', '') or '').strip()

    # Validate password if provided
    raw_password = request.POST.get('murmur_password', '')
    password = raw_password if raw_password != '' else None
    if password is not None:
        if len(password) < 8:
            if is_ajax:
                return JsonResponse({'error': _('Password must be at least 8 characters.')}, status=400)
            messages.error(request, _('Password must be at least 8 characters.'))
            return redirect('profile')
        if not _password_has_supported_chars(password):
            if is_ajax:
                return JsonResponse({'error': _("Password may not contain any of: ' \" ` \\")}, status=400)
            messages.error(request, _("Password may not contain any of: ' \" ` \\"))
            return redirect('profile')

    target_pkid = request.user.pk
    mapped_pkid = _resolve_bg_pkid_for_mockui(request.user, pilot_id_raw)
    if mapped_pkid is not None:
        target_pkid = mapped_pkid

    # Send password directly to BG — BG owns registrations
    try:
        response = _CONTROL_CLIENT.reset_password_for_user(
            user=request.user,
            password=password,
            pkid=target_pkid,
            requested_by=str(request.user.get_username() or 'unknown'),
        )
    except BgSyncError as exc:
        logger.warning('Profile password action failed for user=%s: %s', request.user.pk, exc)
        bg_unavailable = _bg_unavailable_error(exc)
        inactive_message = _('Mumble account inactive, try again later.')
        if is_ajax:
            if bg_unavailable:
                return JsonResponse(
                    {'error': _('BG unavailable'), 'bg_unavailable': True},
                    status=503,
                )
            return JsonResponse(
                {'error': inactive_message, 'bg_unavailable': False},
                status=409,
            )
        messages.warning(request, _('BG unavailable') if bg_unavailable else inactive_message)
        return redirect('profile')

    resolved_password = response.get('password')
    if password is not None:
        msg = _('Murmur password updated.')
    else:
        msg = _('Murmur password has been reset.')

    if is_ajax:
        payload = {'status': 'ok', 'message': str(msg)}
        if password is None and resolved_password:
            payload['password'] = resolved_password
        return JsonResponse(payload)

    if password is None and resolved_password:
        request.session['murmur_temp_password'] = resolved_password

    messages.success(request, msg)
    return redirect('profile')


def _mockui_enabled() -> bool:
    if bool(getattr(settings, 'MOCKUI', False)):
        return True
    return str(getattr(settings, 'UI', '') or '').strip().lower() == 'mock'


def _resolve_bg_pkid_for_mockui(user, pilot_id_raw: str) -> int | None:
    """Map selected character_id (or user) to Eve user_id for BG control payloads."""
    EveCharacter, db = _eve_char_setup()
    if EveCharacter is None or db is None:
        return None

    if pilot_id_raw:
        try:
            character_id = int(pilot_id_raw)
        except ValueError:
            return None
        row = (
            EveCharacter.objects.using(db)
            .filter(character_id=character_id, pending_delete=False)
            .values('user_id')
            .first()
        )
        if row and row.get('user_id') is not None:
            return int(row['user_id'])
        return None

    resolved = _resolved_eve_user_id(user, db=db)
    if resolved is None:
        return None
    return int(resolved)


def _validate_profile_password_choice(request):
    choices = profile_password_pilot_choices(request.user)
    if not choices:
        return None

    valid_ids = {str(choice['character_id']) for choice in choices}
    pilot_id = str(request.POST.get('pilot_id', '') or '').strip()
    if pilot_id and pilot_id not in valid_ids:
        return False
    return True


@require_POST
@login_required
def profile_reset_password(request):
    selection = _validate_profile_password_choice(request)
    if selection is None:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': _('Forbidden')}, status=403)
        return HttpResponseForbidden()
    if selection is False:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': _('Invalid pilot selection.')}, status=400)
        messages.error(request, _('Invalid pilot selection.'))
        return redirect('profile')
    return _profile_password_action_response(request)


@require_POST
@login_required
def profile_set_password(request):
    selection = _validate_profile_password_choice(request)
    if selection is None:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': _('Forbidden')}, status=403)
        return HttpResponseForbidden()
    if selection is False:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': _('Invalid pilot selection.')}, status=400)
        messages.error(request, _('Invalid pilot selection.'))
        return redirect('profile')
    return _profile_password_action_response(request)


@require_POST
@login_required
def deactivate(request, server_id):
    mumble_user = _user_registration(request.user, server_id=server_id)
    if mumble_user is None:
        messages.error(request, _('No Murmur account found.'))
        return redirect('profile')

    try:
        _unregister_remote_registration(mumble_user)
    except BgSyncError as exc:
        logger.warning(
            'Failed to unregister Murmur user for MumbleUser pk=%s on server=%s: %s',
            mumble_user.pk,
            mumble_user.server_id,
            exc,
        )
        messages.error(
            request,
            _('Murmur account could not be deactivated because Murmur registration sync failed.'),
        )
        return redirect('profile')

    if _host_murmur_models_available():
        try:
            mumble_user.delete()
        except MumbleUser.DoesNotExist:
            messages.error(request, _('No Murmur account found.'))
            return redirect('profile')
    messages.success(request, _('Murmur account deactivated.'))
    return redirect('profile')


def _can_manage_mumble(user):
    if not user.is_authenticated:
        return False
    return (
        user.is_superuser
        or user.has_perm('mumble.manage_mumble_admin')
        or user.has_perm('mumble_fg.manage_mumble_admin')
    )


def _can_manage_mumble_admin(user):
    return _can_manage_mumble(user)


def _can_act_as_mumble_moderator(user):
    """Authorization for cross-user moderator endpoints (Cube Edit-User page).

    Either credential is sufficient — a Cube cube-admin who is not a Mumble
    admin can fix everyday user state, and a Mumble admin who is not a Cube
    moderator retains the existing FG admin surface.
    """
    if not user.is_authenticated:
        return False
    if user.is_staff or user.is_superuser:
        return True
    if user.groups.filter(name='cube-admin').exists():
        return True
    return user.has_perm('mumble.manage_mumble_admin') or user.has_perm('mumble_fg.manage_mumble_admin')


@login_required
def mumble_manage(request):
    if not _can_manage_mumble(request.user):
        return HttpResponseForbidden()
    servers = safe_list_servers()
    order_map = {server.pk: index for index, server in enumerate(servers)}
    mumble_users = get_runtime_service().attach_users(
        safe_registration_inventory(servers=servers)
    )
    mumble_users.sort(
        key=lambda registration: (
            order_map.get(registration.server_id, 999999),
            str(getattr(registration, 'username', '') or '').lower(),
        )
    )
    can_manage_contract = request.user.is_superuser
    return render(
        request,
        'fg/manage.html',
        {
            'mumble_users': mumble_users,
            'can_manage_admin': _can_manage_mumble_admin(request.user),
            'can_manage_contract': can_manage_contract,
        },
    )


@require_POST
@login_required
def toggle_admin(request, mumble_user_id):
    if not _can_manage_mumble_admin(request.user):
        return HttpResponseForbidden()
    if not _host_murmur_models_available():
        raise Http404()
    mumble_user = get_object_or_404(MumbleUser, pk=mumble_user_id)
    return _toggle_admin_for_registration(request, mumble_user)


def _toggle_admin_for_registration(request, mumble_user):
    mumble_user.is_mumble_admin = not mumble_user.is_mumble_admin
    mumble_user.groups = _compute_groups(mumble_user.user, mumble_user=mumble_user)
    if _host_murmur_models_available() and hasattr(mumble_user, 'save'):
        mumble_user.save(update_fields=['is_mumble_admin', 'groups', 'updated_at'])
    synced_sessions = 0
    try:
        synced_sessions = _sync_live_admin_membership(mumble_user)
    except BgSyncError as exc:
        logger.warning(
            'Failed to sync live Murmur admin membership for MumbleUser pk=%s on server=%s: %s',
            mumble_user.pk,
            mumble_user.server_id,
            exc,
        )
        _notify_superuser_handshake_failure(request, exc)
        messages.warning(
            request,
            _('Admin status was updated, but live Murmur session sync failed. Connected users may need to reconnect.'),
        )
    status = _('granted') if mumble_user.is_mumble_admin else _('revoked')
    messages.success(request, _('Murmur admin %(status)s for %(user)s.') % {
        'status': status, 'user': mumble_user.username,
    })
    if synced_sessions:
        messages.info(
            request,
            _('Updated %(count)s active Murmur session(s) immediately.') % {'count': synced_sessions},
        )
    return redirect('mumble:manage')


@require_POST
@login_required
def toggle_admin_registration(request, pkid: int, server_id: int):
    if not _can_manage_mumble_admin(request.user):
        return HttpResponseForbidden()
    if _host_murmur_models_available():
        mumble_user = get_object_or_404(MumbleUser, user_id=pkid, server_id=server_id)
    else:
        mumble_user = _runtime_registration(pkid, server_id=server_id)
        if mumble_user is None:
            raise Http404()
        mumble_user.user = get_runtime_service().attach_users([mumble_user])[0].user
    return _toggle_admin_for_registration(request, mumble_user)


@require_POST
@login_required
def sync_contract(request, mumble_user_id):
    if not request.user.is_superuser:
        return HttpResponseForbidden()
    if not _host_murmur_models_available():
        raise Http404()

    mumble_user = get_object_or_404(MumbleUser, pk=mumble_user_id)
    return _sync_contract_for_registration(request, mumble_user)


def _sync_contract_for_registration(request, mumble_user):
    try:
        requested_values = {
            'evepilot_id': _coerce_optional_int(request.POST.get('evepilot_id'), field_name='evepilot_id'),
            'corporation_id': _coerce_optional_int(request.POST.get('corporation_id'), field_name='corporation_id'),
            'alliance_id': _coerce_optional_int(request.POST.get('alliance_id'), field_name='alliance_id'),
            'kdf_iterations': _coerce_optional_int(request.POST.get('kdf_iterations'), field_name='kdf_iterations'),
        }
    except BgSyncError as exc:
        messages.error(request, _('Invalid contract metadata: %(error)s') % {'error': exc})
        return redirect('mumble:manage')

    try:
        _sync_contract_metadata(
            mumble_user,
            requested_by=str(getattr(request.user, 'username', 'unknown')),
            is_super=True,
            **requested_values,
        )
        registration = _CONTROL_CLIENT.probe_murmur_registration(mumble_user)
    except BgSyncError as exc:
        logger.warning(
            'Failed to sync contract metadata for MumbleUser pk=%s on server=%s: %s',
            mumble_user.pk,
            mumble_user.server_id,
            exc,
        )
        _notify_superuser_handshake_failure(request, exc)
        messages.warning(
            request,
            _('Contract metadata update request failed: %(error)s') % {'error': exc},
        )
        return redirect('mumble:manage')

    if not registration:
        messages.warning(
            request,
            _('Contract metadata was sent, but probe verification returned no registration row.'),
        )
        return redirect('mumble:manage')

    mismatched_fields = [
        field_name
        for field_name, expected in requested_values.items()
        if registration.get(field_name) != expected
    ]
    if mismatched_fields:
        messages.warning(
            request,
            _('Contract metadata update did not verify for fields: %(fields)s') % {
                'fields': ', '.join(sorted(mismatched_fields)),
            },
        )
        return redirect('mumble:manage')

    messages.success(request, _('Contract metadata synchronized for %(user)s.') % {'user': mumble_user.username})
    return redirect('mumble:manage')


@require_POST
@login_required
def sync_contract_registration(request, pkid: int, server_id: int):
    if not request.user.is_superuser:
        return HttpResponseForbidden()
    if _host_murmur_models_available():
        mumble_user = get_object_or_404(MumbleUser, user_id=pkid, server_id=server_id)
    else:
        mumble_user = _runtime_registration(pkid, server_id=server_id)
        if mumble_user is None:
            raise Http404()
    return _sync_contract_for_registration(request, mumble_user)


# ---------------------------------------------------------------------------
# Cube cube-admin moderator endpoints
# ---------------------------------------------------------------------------


@require_POST
@login_required
def admin_reset_password_for_user(request, user_id: int, server_id: int):
    """Force-reset another user's Murmur password on a specific server.

    Used by the Cube Edit-User page (cube_admin module). Returns the new
    password once in JSON; the caller is responsible for displaying it and
    not persisting it. Permission gate accepts either Cube cube-admin
    membership or the existing ``mumble_fg.manage_mumble_admin`` perm.
    """
    if not _can_act_as_mumble_moderator(request.user):
        return JsonResponse({'error': 'forbidden'}, status=403)

    if _host_murmur_models_available():
        mumble_user = get_object_or_404(MumbleUser, user_id=user_id, server_id=server_id)
    else:
        mumble_user = _runtime_registration(user_id, server_id=server_id)
        if mumble_user is None:
            return JsonResponse({'error': 'not_found'}, status=404)

    requested_by = f'cube_admin:{request.user.pk}'
    try:
        response = _CONTROL_CLIENT.reset_password_for_user(
            mumble_user.user if hasattr(mumble_user, 'user') and mumble_user.user else None,
            pkid=user_id,
            requested_by=requested_by,
        )
    except BgSyncError as exc:
        logger.warning(
            'cube-admin password reset failed for user_id=%s server_id=%s: %s',
            user_id, server_id, exc,
        )
        return JsonResponse({'error': 'bg_sync_failed', 'detail': str(exc)}, status=502)

    password = response.get('password')
    if not password:
        return JsonResponse({'error': 'no_password_in_response'}, status=502)

    return JsonResponse({
        'password': password,
        'server_id': server_id,
        'username': getattr(mumble_user, 'username', '') or '',
    })


@require_POST
@login_required
def admin_clear_certhash(request, user_id: int, server_id: int):
    """Clear another user's stored Murmur certhash on a specific server.

    Murmur reads ``certhash`` lazily on next reconnect, so the next time
    the user connects with a cert, Murmur will rebind it. Same permission
    gate as :func:`admin_reset_password_for_user`.
    """
    if not _can_act_as_mumble_moderator(request.user):
        return JsonResponse({'error': 'forbidden'}, status=403)

    if _host_murmur_models_available():
        get_object_or_404(MumbleUser, user_id=user_id, server_id=server_id)
    else:
        if _runtime_registration(user_id, server_id=server_id) is None:
            return JsonResponse({'error': 'not_found'}, status=404)

    requested_by = f'cube_admin:{request.user.pk}'
    try:
        _CONTROL_CLIENT.clear_certhash_for_user(
            request.user,
            server_id,
            pkid=user_id,
            requested_by=requested_by,
        )
    except BgSyncError as exc:
        logger.warning(
            'cube-admin clear certhash failed for user_id=%s server_id=%s: %s',
            user_id, server_id, exc,
        )
        return JsonResponse({'error': 'bg_sync_failed', 'detail': str(exc)}, status=502)

    return JsonResponse({'ok': True})


# ---------------------------------------------------------------------------
# Mumble ACL (user-facing access control list)
# ---------------------------------------------------------------------------

def _acl_admin_bypass(user):
    return user.is_superuser


def _has_acl_perm(user, codename):
    return user.is_authenticated and (
        _acl_admin_bypass(user)
        or user.has_perm(f'mumble_fg.{codename}')
    )


def _can_view_acl(user):
    return _has_acl_perm(user, 'view_accessrule')


def _controls_tabs(user, active_key: str) -> list[dict[str, object]]:
    tabs: list[dict[str, object]] = []
    if _can_view_acl(user):
        tabs.append(
            {
                'key': 'accessibility',
                'label': _('Accessibility'),
                'url': reverse('mumble:acl_list'),
                'active': active_key == 'accessibility',
            }
        )
    if _can_view_group_mapping(user):
        tabs.append(
            {
                'key': 'groups',
                'label': _('Groups'),
                'url': reverse('mumble:group_mapping'),
                'active': active_key == 'groups',
            }
        )
    if _can_view_temp_links(user):
        tabs.append(
            {
                'key': 'links',
                'label': _('Links'),
                'url': reverse('mumble:temp_links'),
                'active': active_key == 'links',
            }
        )
    if _can_view_server_panels(user):
        tabs.append(
            {
                'key': 'servers',
                'label': _('Servers'),
                'url': reverse('mumble:server_panels'),
                'active': active_key == 'servers',
            }
        )
    return tabs


def _can_create_acl(user):
    return _can_view_acl(user) and _has_acl_perm(user, 'add_accessrule')


def _can_change_acl(user):
    return _can_view_acl(user) and _has_acl_perm(user, 'change_accessrule')


def _can_delete_acl(user):
    return _can_view_acl(user) and _has_acl_perm(user, 'delete_accessrule')


def _can_manage_acl_admin(user):
    return _can_view_acl(user) and (
        _acl_admin_bypass(user)
        or _has_acl_perm(user, 'manage_acl_admin')
    )


def _can_view_acl_admin_any(user):
    return _can_view_acl(user) and (
        _acl_admin_bypass(user)
        or _has_acl_perm(user, 'view_acl_admin_all')
        or _has_acl_perm(user, 'view_acl_admin_my_alliance')
        or _has_acl_perm(user, 'view_acl_admin_my_corp')
    )


def _viewer_org_ids(user) -> tuple[int | None, int | None]:
    if not getattr(user, 'is_authenticated', False):
        return None, None
    main = get_host_adapter().get_main_character(user)
    if not main:
        return None, None
    return (
        int(main.corporation_id) if getattr(main, 'corporation_id', None) else None,
        int(main.alliance_id) if getattr(main, 'alliance_id', None) else None,
    )


def _pilot_org_ids(pilot_character_id: int) -> tuple[int | None, int | None]:
    EveCharacter, db = _eve_char_setup()
    if EveCharacter is None or db is None:
        return None, None

    row = (
        EveCharacter.objects.using(db)
        .filter(character_id=pilot_character_id, pending_delete=False)
        .values('corporation_id', 'alliance_id')
        .first()
    )
    if not row:
        return None, None
    return (
        int(row['corporation_id']) if row.get('corporation_id') else None,
        int(row['alliance_id']) if row.get('alliance_id') else None,
    )


def _can_view_acl_admin_for_pilot(user, pilot_character_id: int, *, pilot_org: tuple[int | None, int | None] | None = None) -> bool:
    if not _can_view_acl_admin_any(user):
        return False
    if _acl_admin_bypass(user) or _has_acl_perm(user, 'view_acl_admin_all'):
        return True

    corp_scope = _has_acl_perm(user, 'view_acl_admin_my_corp')
    alliance_scope = _has_acl_perm(user, 'view_acl_admin_my_alliance')
    if not corp_scope and not alliance_scope:
        return False

    viewer_corp, viewer_alliance = _viewer_org_ids(user)
    pilot_corp, pilot_alliance = pilot_org or _pilot_org_ids(pilot_character_id)
    return (
        bool(corp_scope and viewer_corp and pilot_corp and viewer_corp == pilot_corp)
        or bool(alliance_scope and viewer_alliance and pilot_alliance and viewer_alliance == pilot_alliance)
    )


def _can_manage_acl_admin_for_pilot(user, pilot_character_id: int, *, pilot_org: tuple[int | None, int | None] | None = None) -> bool:
    return _can_manage_acl_admin(user) and _can_view_acl_admin_for_pilot(user, pilot_character_id, pilot_org=pilot_org)


def _sync_acl_rules_after_change(request, *, source, trigger, rule=None, acl_id=None):
    actor_username = request.user.get_username() or 'system'
    return sync_acl_rules_to_bg(
        requested_by=actor_username,
        actor_username=actor_username,
        source=source,
        trigger=trigger,
        rule=rule,
        acl_id=acl_id,
    )


def _acl_sync_failure_message(request, exc):
    messages.warning(
        request,
        _('ACL was updated locally, but BG sync failed: %(error)s.') % {'error': str(exc)},
    )


def _bg_unavailable_error(exc):
    message = str(exc or '')
    lowered = message.lower()
    return (
        'control endpoint unreachable' in lowered
        or 'connection refused' in lowered
        or 'timed out' in lowered
        or 'timedout' in lowered
        or 'control request failed (502)' in lowered
        or 'control request failed (503)' in lowered
        or 'control request failed (504)' in lowered
    )


def _notify_superuser_handshake_failure(request, exc) -> None:
    if not getattr(request.user, 'is_superuser', False):
        return
    if not is_handshake_failure_error(exc):
        return
    messages.warning(
        request,
        _(
            'FG cannot handshake with BG control right now. '
            'If this persists, reset FG/BG handshake state and bootstrap a new key.'
        ),
    )


def _resolve_name_for_rule(rule):
    """Resolve an entity name for display. Returns the name or '-'."""
    from .admin import _get_eve_character_model, _get_db_for_eve
    EveCharacter = _get_eve_character_model()
    if EveCharacter is None:
        return '-'
    db = _get_db_for_eve() or 'default'
    if rule.entity_type == ENTITY_TYPE_ALLIANCE:
        row = EveCharacter.objects.using(db).filter(alliance_id=rule.entity_id).values('alliance_name').first()
        return (row or {}).get('alliance_name', '-')
    elif rule.entity_type == ENTITY_TYPE_CORPORATION:
        row = EveCharacter.objects.using(db).filter(corporation_id=rule.entity_id).values('corporation_name').first()
        return (row or {}).get('corporation_name', '-')
    elif rule.entity_type == ENTITY_TYPE_PILOT:
        row = EveCharacter.objects.using(db).filter(character_id=rule.entity_id).values('character_name').first()
        return (row or {}).get('character_name', '-')
    return '-'


@login_required
def mumble_controls(request):
    if _can_view_acl(request.user):
        return redirect('mumble:acl_list')
    if _can_view_group_mapping(request.user):
        return redirect('mumble:group_mapping')
    if _can_view_temp_links(request.user):
        return redirect('mumble:temp_links')
    if _can_view_server_panels(request.user):
        return redirect('mumble:server_panels')
    return HttpResponseForbidden()


@login_required
def acl_list(request):
    if not _can_view_acl(request.user):
        return HttpResponseForbidden()

    rules = list(AccessRule.objects.all())
    pilot_orgs = _pilot_org_map(
        [int(rule.entity_id) for rule in rules if rule.entity_type == ENTITY_TYPE_PILOT]
    )
    for rule in rules:
        rule.resolved_name = _resolve_name_for_rule(rule)
        rule.can_view_acl_admin = False
        rule.can_manage_acl_admin = False
        if rule.entity_type == ENTITY_TYPE_PILOT:
            pilot_org = pilot_orgs.get(int(rule.entity_id))
            rule.can_view_acl_admin = (not rule.deny) and _can_view_acl_admin_for_pilot(
                request.user,
                int(rule.entity_id),
                pilot_org=pilot_org,
            )
            rule.can_manage_acl_admin = (not rule.deny) and _can_manage_acl_admin_for_pilot(
                request.user,
                int(rule.entity_id),
                pilot_org=pilot_org,
            )

    return render(request, 'fg/acl.html', {
        'rules': rules,
        'controls_tabs': _controls_tabs(request.user, 'accessibility'),
        'can_create_acl': _can_create_acl(request.user),
        'can_change_acl': _can_change_acl(request.user),
        'can_delete_acl': _can_delete_acl(request.user),
        'can_sync_acl': _can_change_acl(request.user),
        'can_view_acl_admin': _can_view_acl_admin_any(request.user),
        'can_manage_acl_admin': _can_manage_acl_admin(request.user),
        'search_url': reverse('mumble:acl_search'),
        'batch_url': reverse('mumble:acl_batch_create'),
        'eligible_url': reverse('mumble:acl_eligible'),
        'blocked_url': reverse('mumble:acl_blocked'),
        'sync_url': reverse('mumble:acl_sync'),
    })


@login_required
def acl_search(request):
    if not _can_create_acl(request.user):
        return JsonResponse({'error': 'Forbidden'}, status=403)

    from .admin import _search_eve_entities
    query = request.GET.get('q', '').strip()
    entity_type = request.GET.get('type', '').strip() or None
    if entity_type and entity_type not in (ENTITY_TYPE_ALLIANCE, ENTITY_TYPE_CORPORATION, ENTITY_TYPE_PILOT):
        entity_type = None
    results = _search_eve_entities(query, entity_type=entity_type)
    return JsonResponse({'results': results})


@require_POST
@login_required
def acl_batch_create(request):
    if not _can_create_acl(request.user):
        return JsonResponse({'error': 'Forbidden'}, status=403)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    entities = data.get('entities', [])
    note = (data.get('note') or '').strip()
    deny = bool(data.get('deny', False))
    acl_admin_requested = bool(data.get('acl_admin', False))
    created_by = request.user.get_username()

    if not entities:
        return JsonResponse({'error': 'No entities provided'}, status=400)
    if acl_admin_requested and deny:
        return JsonResponse({'error': 'Denied pilots cannot be marked as ACL admin.'}, status=400)
    if acl_admin_requested and not _can_manage_acl_admin(request.user):
        return JsonResponse({'error': 'Forbidden'}, status=403)

    created = []
    skipped = []
    for entry in entities:
        entity_id = entry.get('entity_id')
        entity_type = entry.get('entity_type')
        if not entity_id or entity_type not in (ENTITY_TYPE_ALLIANCE, ENTITY_TYPE_CORPORATION, ENTITY_TYPE_PILOT):
            continue
        acl_admin = False
        if acl_admin_requested:
            if entity_type != ENTITY_TYPE_PILOT:
                return JsonResponse({'error': 'ACL admin can only be set for pilot rules.'}, status=400)
            if _pilot_has_denied_corp_or_alliance(int(entity_id)):
                return JsonResponse(
                    {'error': 'Pilot cannot be ACL admin while alliance or corporation deny rules apply.'},
                    status=400,
                )
            if not _can_manage_acl_admin_for_pilot(request.user, int(entity_id)):
                return JsonResponse({'error': 'Forbidden'}, status=403)
            acl_admin = True
        rule, was_created = AccessRule.objects.get_or_create(
            entity_id=entity_id,
            defaults={
                'entity_type': entity_type,
                'deny': deny,
                'acl_admin': acl_admin,
                'note': note,
                'created_by': created_by,
            },
        )
        if was_created:
            created.append(entity_id)
            append_access_rule_audit(
                action=ACL_AUDIT_ACTION_CREATE,
                actor_username=request.user.get_username(),
                rule=rule,
                source='acl_ui_batch_create',
            )
        else:
            skipped.append(entity_id)

    sync_status = 'not_needed'
    sync_error = ''
    if created:
        try:
            response = _sync_acl_rules_after_change(
                request,
                source='acl_ui_batch_create_sync',
                trigger='implicit',
            )
        except BgSyncError as exc:
            sync_status = 'failed'
            sync_error = str(exc)
        else:
            sync_status = str(response.get('status', 'completed')).lower()

    return JsonResponse({
        'created': len(created),
        'skipped': len(skipped),
        'skipped_ids': skipped,
        'sync_status': sync_status,
        'sync_error': sync_error,
    })


def _no_cache_json(data, **kwargs):
    """Return a JsonResponse with no-cache headers."""
    response = JsonResponse(data, **kwargs)
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response


def _acl_rule_sets():
    """Parse ACL rules into categorised ID sets via fgbg_common."""
    rules = list(
        AccessRule.objects.values('entity_id', 'entity_type', 'deny')
    )
    return build_rule_sets(rules)


def _eve_char_setup():
    from .admin import _get_eve_character_model, _get_db_for_eve
    return _get_eve_character_model(), _get_db_for_eve()


def _char_list(queryset):
    return [
        {
            'character_name': c['character_name'],
            'corporation': c['corporation_name'] or '-',
            'alliance': c['alliance_name'] or '-',
        }
        for c in queryset.values(
            'character_id', 'character_name', 'corporation_name', 'alliance_name',
        ).order_by('character_name')
    ]


def _char_list_from_rows(rows):
    pilots = [
        {
            'character_name': row['character_name'],
            'corporation': row['corporation_name'] or '-',
            'alliance': row['alliance_name'] or '-',
        }
        for row in rows
    ]
    pilots.sort(key=lambda pilot: pilot['character_name'].lower())
    return pilots


_DENIAL_REASON_LABELS = {
    ENTITY_TYPE_ALLIANCE: 'alliance',
    ENTITY_TYPE_CORPORATION: 'corp',
    ENTITY_TYPE_PILOT: 'pilot',
}


def _matching_character_rows(EveCharacter, db, rs):
    """Host-specific: query EVE character DB for all characters matching any rule."""
    from django.db.models import Q

    ids = all_referenced_ids(rs)
    q = Q()
    if ids['alliance_ids']:
        q |= Q(alliance_id__in=ids['alliance_ids'])
    if ids['corporation_ids']:
        q |= Q(corporation_id__in=ids['corporation_ids'])
    if ids['pilot_ids']:
        q |= Q(character_id__in=ids['pilot_ids'])
    if not q:
        return []

    return list(
        EveCharacter.objects.using(db)
        .filter(q, pending_delete=False)
        .values(
            'user_id',
            'character_id',
            'character_name',
            'corporation_id',
            'corporation_name',
            'alliance_id',
            'alliance_name',
        )
        .order_by('user_id', 'character_name')
    )


def _main_character_rows(EveCharacter, db, user_ids):
    """Host-specific: fetch main character for each user."""
    mains = {}
    queryset = (
        EveCharacter.objects.using(db)
        .filter(user_id__in=user_ids, pending_delete=False)
        .values(
            'user_id',
            'character_id',
            'character_name',
            'corporation_name',
            'alliance_name',
            'is_main',
        )
        .order_by('user_id', '-is_main', 'character_name')
    )
    for row in queryset:
        mains.setdefault(row['user_id'], row)
    return mains


def _pilot_has_denied_corp_or_alliance(pilot_character_id: int) -> bool:
    """Return True when this pilot account matches any corp/alliance deny rule."""
    EveCharacter, db = _eve_char_setup()
    if EveCharacter is None or db is None:
        return False

    pilot_row = (
        EveCharacter.objects.using(db)
        .filter(character_id=pilot_character_id, pending_delete=False)
        .values('user_id')
        .first()
    )
    if not pilot_row:
        return False

    rs = _acl_rule_sets()
    denied_corps = rs['denied_corps']
    denied_alliances = rs['denied_alliances']
    if not denied_corps and not denied_alliances:
        return False

    account_rows = (
        EveCharacter.objects.using(db)
        .filter(user_id=pilot_row['user_id'], pending_delete=False)
        .values('corporation_id', 'alliance_id')
    )
    for row in account_rows:
        if row['corporation_id'] in denied_corps:
            return True
        if row['alliance_id'] in denied_alliances:
            return True
    return False


def _pilot_org_map(pilot_character_ids: list[int]) -> dict[int, tuple[int | None, int | None]]:
    EveCharacter, db = _eve_char_setup()
    if EveCharacter is None or db is None or not pilot_character_ids:
        return {}
    rows = (
        EveCharacter.objects.using(db)
        .filter(character_id__in=pilot_character_ids, pending_delete=False)
        .values('character_id', 'corporation_id', 'alliance_id')
    )
    mapped: dict[int, tuple[int | None, int | None]] = {}
    for row in rows:
        character_id = int(row['character_id'])
        mapped[character_id] = (
            int(row['corporation_id']) if row.get('corporation_id') else None,
            int(row['alliance_id']) if row.get('alliance_id') else None,
        )
    return mapped


def _resolved_eve_user_id(user, *, db: str):
    if not getattr(user, 'is_authenticated', False):
        return None
    if db == 'default':
        return user.id
    user_model = get_user_model()
    mapped = (
        user_model.objects.using(db)
        .filter(username=getattr(user, 'username', ''))
        .values_list('id', flat=True)
        .first()
    )
    return mapped or user.id


def _blocked_main_list(EveCharacter, db, rs):
    """Delegate to fgbg_common with host-specific data queries."""
    char_rows = _matching_character_rows(EveCharacter, db, rs)
    blocked_reasons = blocked_user_reasons(account_rule_decisions(char_rows, rs))
    if not blocked_reasons:
        return []
    mains = _main_character_rows(EveCharacter, db, blocked_reasons.keys())
    return _common_blocked_main_list(char_rows, mains, rs)


def _eligible_account_list(EveCharacter, db, rs):
    """Delegate to fgbg_common with host-specific data queries."""
    char_rows = _matching_character_rows(EveCharacter, db, rs)
    blocked_reasons = blocked_user_reasons(account_rule_decisions(char_rows, rs))
    if not blocked_reasons:
        all_user_ids = {row['user_id'] for row in char_rows}
    else:
        all_user_ids = {row['user_id'] for row in char_rows} - set(blocked_reasons)
    mains = _main_character_rows(EveCharacter, db, all_user_ids)
    return _common_eligible_account_list(char_rows, mains, rs)


def profile_password_pilot_choices(user):
    if not getattr(user, 'is_authenticated', False):
        return []

    EveCharacter, db = _eve_char_setup()
    if EveCharacter is None or db is None:
        return []
    eve_user_id = _resolved_eve_user_id(user, db=db)
    if eve_user_id is None:
        return []

    rs = _acl_rule_sets()
    char_rows = _matching_character_rows(EveCharacter, db, rs)
    if eve_user_id in blocked_user_reasons(account_rule_decisions(char_rows, rs)):
        return []

    allowed_rows = []
    for row in char_rows:
        if row['user_id'] != eve_user_id:
            continue
        match = explicit_rule_match(rs, row) or {}
        if match.get('action') != 'allow':
            continue
        allowed_rows.append((row, match))

    if not allowed_rows:
        return []

    main = _main_character_rows(EveCharacter, db, [eve_user_id]).get(eve_user_id)
    if not main:
        return []

    pilot_choices = [
        {
            'character_id': main['character_id'],
            'character_name': main['character_name'],
            'is_main': True,
        }
    ]
    seen_ids = {main['character_id']}
    alt_rows = sorted(
        (
            row
            for row, match in allowed_rows
            if match['reason_type'] == ENTITY_TYPE_PILOT
            and row['character_id'] != main['character_id']
        ),
        key=lambda row: row['character_name'].lower(),
    )
    for row in alt_rows:
        if row['character_id'] in seen_ids:
            continue
        seen_ids.add(row['character_id'])
        pilot_choices.append(
            {
                'character_id': row['character_id'],
                'character_name': row['character_name'],
                'is_main': False,
            }
        )
    return pilot_choices


@login_required
def acl_eligible(request):
    if not _can_view_acl(request.user):
        return _no_cache_json({'error': 'Forbidden'}, status=403)

    EveCharacter, db = _eve_char_setup()
    if EveCharacter is None or db is None:
        return _no_cache_json({'error': 'EVE data unavailable'}, status=503)

    rs = _acl_rule_sets()
    pilots = _eligible_account_list(EveCharacter, db, rs)
    return _no_cache_json({'pilots': pilots, 'count': len(pilots)})


@login_required
def acl_blocked(request):
    """Return blocked accounts as their main pilot plus the most specific deny reason."""
    if not _can_view_acl(request.user):
        return _no_cache_json({'error': 'Forbidden'}, status=403)

    EveCharacter, db = _eve_char_setup()
    if EveCharacter is None or db is None:
        return _no_cache_json({'error': 'EVE data unavailable'}, status=503)

    rs = _acl_rule_sets()
    pilots = _blocked_main_list(EveCharacter, db, rs)
    return _no_cache_json({'pilots': pilots, 'count': len(pilots)})


@require_POST
@login_required
def acl_sync(request):
    if not _can_change_acl(request.user):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': 'Forbidden'}, status=403)
        return HttpResponseForbidden()

    # The Sync button doubles as the "apply group grants now" affordance.
    # Fault-isolated: grant trouble must not block pushing the current rules.
    try:
        from .acl_grants import reconcile_group_grants
        reconcile_group_grants(
            actor_username=request.user.get_username(),
            source='acl_ui_sync',
        )
    except Exception:
        logger.exception('Group-grant reconcile failed during manual ACL sync')

    try:
        response = _sync_acl_rules_after_change(
            request,
            source='acl_ui_sync',
            trigger='manual',
        )
    except BgSyncError as exc:
        bg_unavailable = _bg_unavailable_error(exc)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            if bg_unavailable:
                return JsonResponse(
                    {'error': _('BG unavailable'), 'bg_unavailable': True},
                    status=503,
                )
            return JsonResponse(
                {
                    'error': _('ACL sync failed: %(error)s.') % {'error': str(exc)},
                    'bg_unavailable': False,
                },
                status=502,
            )
        if bg_unavailable:
            messages.warning(request, _('BG unavailable'))
        else:
            messages.warning(request, _('ACL sync failed: %(error)s.') % {'error': str(exc)})
    else:
        total = response.get('total')
        if not isinstance(total, int):
            total = AccessRule.objects.count()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'status': 'completed',
                'message': _('ACL synchronized to BG (%(count)s entries).') % {'count': total},
                'total': total,
            })
        messages.success(request, _('ACL synchronized to BG (%(count)s entries).') % {'count': total})
    return redirect('mumble:acl_list')


@require_POST
@login_required
def acl_toggle_deny(request, rule_id):
    if not _can_change_acl(request.user):
        return HttpResponseForbidden()

    rule = get_object_or_404(AccessRule, pk=rule_id)
    previous = access_rule_snapshot(rule)
    rule.deny = not rule.deny
    update_fields = ['deny', 'updated_at']
    if rule.deny:
        rule.acl_admin = False
        update_fields.append('acl_admin')
    if rule.source == ACCESS_RULE_SOURCE_GROUP_GRANT:
        # A human touched it: adopt as manual so the group-grant reconciler
        # never garbage-collects an admin's explicit decision.
        rule.source = ACCESS_RULE_SOURCE_MANUAL
        update_fields.append('source')
    rule.save(update_fields=update_fields)
    append_access_rule_audit(
        action=ACL_AUDIT_ACTION_UPDATE,
        actor_username=request.user.get_username(),
        rule=rule,
        source='acl_ui_toggle_deny',
        previous=previous,
    )
    try:
        _sync_acl_rules_after_change(
            request,
            source='acl_ui_toggle_deny_sync',
            trigger='implicit',
            rule=rule,
        )
    except BgSyncError as exc:
        _acl_sync_failure_message(request, exc)
    return redirect('mumble:acl_list')


@require_POST
@login_required
def acl_toggle_admin(request, rule_id):
    if not _can_manage_acl_admin(request.user):
        return HttpResponseForbidden()

    rule = get_object_or_404(AccessRule, pk=rule_id)
    if rule.entity_type != ENTITY_TYPE_PILOT:
        messages.warning(request, _('ACL admin can only be set for pilot rules.'))
        return redirect('mumble:acl_list')
    if rule.deny:
        messages.warning(request, _('Denied pilots cannot be marked as ACL admin.'))
        return redirect('mumble:acl_list')
    if not _can_manage_acl_admin_for_pilot(request.user, int(rule.entity_id)):
        return HttpResponseForbidden()

    previous = access_rule_snapshot(rule)
    target_admin = not rule.acl_admin
    if target_admin:
        if _pilot_has_denied_corp_or_alliance(int(rule.entity_id)):
            messages.warning(
                request,
                _('Pilot cannot be ACL admin while alliance or corporation deny rules apply.'),
            )
            return redirect('mumble:acl_list')

    rule.acl_admin = target_admin
    update_fields = ['acl_admin', 'updated_at']
    if rule.source == ACCESS_RULE_SOURCE_GROUP_GRANT:
        # Adopt on manual edit — see acl_toggle_deny.
        rule.source = ACCESS_RULE_SOURCE_MANUAL
        update_fields.append('source')
    rule.save(update_fields=update_fields)
    append_access_rule_audit(
        action=ACL_AUDIT_ACTION_UPDATE,
        actor_username=request.user.get_username(),
        rule=rule,
        source='acl_ui_toggle_admin',
        previous=previous,
    )
    try:
        _sync_acl_rules_after_change(
            request,
            source='acl_ui_toggle_admin_sync',
            trigger='implicit',
            rule=rule,
        )
    except BgSyncError as exc:
        _acl_sync_failure_message(request, exc)
    return redirect('mumble:acl_list')


@require_POST
@login_required
def acl_delete(request, rule_id):
    if not _can_delete_acl(request.user):
        return HttpResponseForbidden()

    rule = get_object_or_404(AccessRule, pk=rule_id)
    append_access_rule_audit(
        action=ACL_AUDIT_ACTION_DELETE,
        actor_username=request.user.get_username(),
        rule=rule,
        source='acl_ui_delete',
        previous=access_rule_snapshot(rule),
    )
    deleted_acl_id = rule.pk
    rule.delete()
    try:
        _sync_acl_rules_after_change(
            request,
            source='acl_ui_delete_sync',
            trigger='implicit',
            rule=rule,
            acl_id=deleted_acl_id,
        )
    except BgSyncError as exc:
        _acl_sync_failure_message(request, exc)
    messages.success(request, _('ACL entry deleted.'))
    return redirect('mumble:acl_list')


# ---------------------------------------------------------------------------
# Cube Group -> Murmur Group Mapping
# ---------------------------------------------------------------------------


def _group_mapping_admin_bypass(user):
    return user.is_superuser


def _has_group_mapping_perm(user, codename: str) -> bool:
    return user.is_authenticated and (
        _group_mapping_admin_bypass(user)
        or user.has_perm(f'mumble_fg.{codename}')
    )


def _can_view_group_mapping(user) -> bool:
    return _has_group_mapping_perm(user, 'view_group_mapping')


def _can_change_group_mapping(user) -> bool:
    return _can_view_group_mapping(user) and _has_group_mapping_perm(user, 'change_group_mapping')


def _temp_links_admin_bypass(user):
    return user.is_superuser


def _has_temp_links_perm(user, codename: str) -> bool:
    return user.is_authenticated and (
        _temp_links_admin_bypass(user)
        or user.has_perm(f'mumble_fg.{codename}')
    )


def _user_in_temp_link_editor_groups(user) -> bool:
    if not getattr(user, 'is_authenticated', False):
        return False
    try:
        from fg.models import TempLinkSettings
        settings = TempLinkSettings.load()
        editor_groups = settings.editor_groups.all()
        if not editor_groups:
            return False
        adapter = get_host_adapter()
        memberships = adapter.get_approved_group_memberships(user)
        member_group_ids = {m.group_id for m in memberships}
        return any(g.pk in member_group_ids for g in editor_groups)
    except Exception:
        return False


def _can_view_temp_links(user) -> bool:
    return _has_temp_links_perm(user, 'view_temp_links') or _user_in_temp_link_editor_groups(user)


def _can_change_temp_links(user) -> bool:
    in_editor = _user_in_temp_link_editor_groups(user)
    can_view = _has_temp_links_perm(user, 'view_temp_links') or in_editor
    return can_view and (_has_temp_links_perm(user, 'change_temp_links') or in_editor)


def _parse_duration_hours(value: str) -> int:
    try:
        normalized = int(str(value or '').strip() or '3')
    except (TypeError, ValueError) as exc:
        raise ValueError('Duration must be an integer number of hours') from exc
    if normalized <= 0 or normalized > 24:
        raise ValueError('Duration must be between 1 and 24 hours')
    return normalized


def _parse_max_uses(value: str) -> int | None:
    normalized = str(value or '').strip()
    if not normalized:
        return None
    try:
        parsed = int(normalized)
    except (TypeError, ValueError) as exc:
        raise ValueError('Max uses must be an integer') from exc
    if parsed <= 0:
        raise ValueError('Max uses must be greater than zero')
    return parsed


def _temp_link_is_usable(link: TempLink) -> bool:
    if not link.is_active:
        return False
    if link.expires_at <= now():
        return False
    if link.max_uses is not None and link.use_count >= link.max_uses:
        return False
    return True


@login_required
def temp_links(request):
    if not _can_view_temp_links(request.user):
        return HttpResponseForbidden()

    servers = [server for server in safe_list_servers() if server.is_active]
    rows = []
    for link in TempLink.objects.order_by('-created_at'):
        rows.append(
            {
                'link': link,
                'public_url': request.build_absolute_uri(reverse('mumble:temp_link_public', args=[link.token])),
                'usable': _temp_link_is_usable(link),
            }
        )

    return render(
        request,
        'fg/temp_links.html',
        {
            'controls_tabs': _controls_tabs(request.user, 'links'),
            'servers': servers,
            'link_rows': rows,
            'can_change_temp_links': _can_change_temp_links(request.user),
            'default_duration_hours': 3,
            'default_groups_csv': 'Guest',
        },
    )


@require_POST
@login_required
def temp_link_create(request):
    if not _can_change_temp_links(request.user):
        return HttpResponseForbidden()

    servers = [server for server in safe_list_servers() if server.is_active]
    server = _resolve_server_from_selector(servers, str(request.POST.get('server', '') or '').strip())
    if server is None:
        messages.error(request, _('Select a valid Mumble server.'))
        return redirect('mumble:temp_links')

    label = str(request.POST.get('label', '') or '').strip()
    groups_csv = str(request.POST.get('groups_csv', '') or 'Guest').strip() or 'Guest'
    try:
        duration_hours = _parse_duration_hours(str(request.POST.get('duration_hours', '') or '24'))
        max_uses = _parse_max_uses(str(request.POST.get('max_uses', '') or ''))
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect('mumble:temp_links')

    link = TempLink.objects.create(
        label=label,
        token=secrets.token_hex(24),
        server_key=_server_selector_value(server),
        server_name=str(server.name or ''),
        groups_csv=groups_csv,
        max_uses=max_uses,
        expires_at=now() + timedelta(hours=duration_hours),
        created_by_username=request.user.get_username() or '',
    )
    messages.success(request, _('Temp link created.'))
    return redirect('mumble:temp_links')


@require_POST
@login_required
def temp_link_toggle_active(request, link_id: int):
    if not _can_change_temp_links(request.user):
        return HttpResponseForbidden()
    link = get_object_or_404(TempLink, pk=link_id)
    link.is_active = not link.is_active
    link.save(update_fields=['is_active', 'updated_at'])
    if not link.is_active:
        try:
            _CONTROL_CLIENT.revoke_temp_link(
                link_token=link.token,
                requested_by=request.user.get_username() or 'unknown',
            )
        except BgSyncError as exc:
            messages.warning(request, _('Link disabled locally, but BG revoke failed: %(error)s') % {'error': str(exc)})
    messages.success(request, _('Temp link updated.'))
    return redirect('mumble:temp_links')


@require_POST
@login_required
def temp_link_delete(request, link_id: int):
    if not _can_change_temp_links(request.user):
        return HttpResponseForbidden()
    link = get_object_or_404(TempLink, pk=link_id)
    try:
        _CONTROL_CLIENT.revoke_temp_link(
            link_token=link.token,
            requested_by=request.user.get_username() or 'unknown',
        )
    except BgSyncError as exc:
        messages.warning(request, _('BG revoke failed before delete: %(error)s') % {'error': str(exc)})
    link.delete()
    messages.success(request, _('Temp link deleted.'))
    return redirect('mumble:temp_links')


def temp_link_public(request, token: str):
    link = get_object_or_404(TempLink, token=str(token or '').strip())
    usable = _temp_link_is_usable(link)
    credentials = None
    error_message = ''

    if request.method == 'POST':
        display_name = str(request.POST.get('display_name', '') or '').strip()
        if not usable:
            error_message = _('This temp link is no longer active.')
        elif not display_name:
            error_message = _('Display name is required.')
        else:
            try:
                response = _CONTROL_CLIENT.redeem_temp_link(
                    server_key=link.server_key,
                    display_name=display_name,
                    groups=link.groups_csv,
                    expires_at=link.expires_at.isoformat(),
                    link_token=link.token,
                    requested_by=f'temp-link:{link.token[:12]}',
                )
            except BgSyncError as exc:
                error_message = str(exc)
            else:
                link.use_count += 1
                link.last_redeemed_at = now()
                if link.max_uses is not None and link.use_count >= link.max_uses:
                    link.is_active = False
                link.save(update_fields=['use_count', 'last_redeemed_at', 'is_active', 'updated_at'])
                # Mumble's connect dialog has separate address and port
                # fields and rejects a pasted 'host:port', so hand the guest
                # the two halves instead of the raw address.
                host, port = split_host_port(response.get('address') or '')
                credentials = {
                    'server_label': response.get('server_name') or link.server_name,
                    'address': host,
                    'port': port,
                    'username': response.get('username') or '',
                    'display_name': response.get('display_name') or display_name,
                    'password': response.get('password') or '',
                }
                usable = _temp_link_is_usable(link)

    return render(
        request,
        'fg/temp_link_public.html',
        {
            'link': link,
            'usable': usable,
            'error_message': error_message,
            'credentials': credentials,
        },
    )


def _server_selector_value(server) -> str:
    return str(getattr(server, 'server_key', '') or '').strip()


def _resolve_server_from_selector(servers, selector: str):
    normalized = str(selector or '').strip()
    if not normalized:
        return None
    return next((server for server in servers if _server_selector_value(server) == normalized), None)


def _snapshot_is_stale(snapshot: MurmurInventorySnapshot | None) -> bool:
    if snapshot is None or snapshot.fetched_at is None:
        return True
    freshness_seconds = int(snapshot.freshness_seconds or 600)
    return (now() - snapshot.fetched_at).total_seconds() >= freshness_seconds


def _load_inventory_snapshot(server, *, refresh: bool = False):
    local_snapshot = MurmurInventorySnapshot.objects.filter(server_key=_server_selector_value(server)).first()
    if refresh or _snapshot_is_stale(local_snapshot):
        try:
            payload = _CONTROL_CLIENT.get_server_inventory(_server_selector_value(server), refresh=refresh)
        except BgSyncError as exc:
            return local_snapshot, str(exc)
        local_snapshot = store_inventory_snapshot(payload)
        return local_snapshot, ''
    return local_snapshot, ''


def _inventory_group_names(snapshot: MurmurInventorySnapshot | None) -> list[str]:
    inventory = getattr(snapshot, 'inventory', {}) or {}
    names = set()
    for group in inventory.get('root_groups', []):
        group_name = str(group.get('name') or '').strip()
        if group_name:
            names.add(group_name)
    for channel in inventory.get('channels', []):
        for group in channel.get('groups', []):
            group_name = str(group.get('name') or '').strip()
            if group_name:
                names.add(group_name)
    return sorted(names, key=str.lower)


def _divergence_rows(selected_server, selected_snapshot, servers):
    rows = []
    selected_inventory = getattr(selected_snapshot, 'inventory', {}) or {}
    selected_groups = set(_inventory_group_names(selected_snapshot))
    selected_summary = dict(selected_inventory.get('summary') or {})
    for server in servers:
        if selected_server is not None and server.pk == selected_server.pk:
            continue
        snapshot = MurmurInventorySnapshot.objects.filter(server_key=_server_selector_value(server)).first()
        if snapshot is None:
            rows.append({
                'server_key': _server_selector_value(server),
                'server_label': server.name,
                'state': 'missing',
                'message': 'No imported snapshot',
            })
            continue
        inventory = snapshot.inventory or {}
        inventory_groups = set(_inventory_group_names(snapshot))
        summary = dict(inventory.get('summary') or {})
        reasons = []
        if inventory_groups != selected_groups:
            reasons.append('Murmur groups differ')
        if summary != selected_summary:
            reasons.append('Channel/ACL summary differs')
        rows.append({
            'server_id': server.pk,
            'server_label': server.name,
            'state': 'diverged' if reasons else 'aligned',
            'message': '; '.join(reasons) if reasons else 'Aligned',
            'fetched_at': snapshot.fetched_at,
        })
    return rows


def _mapping_rows(selected_cube_group_name: str | None, available_group_names: list[str]):
    mapped_names = mapped_murmur_groups_for_cube_group(selected_cube_group_name) if selected_cube_group_name else []
    mapped_name_set = set(mapped_names)
    available_set = set(available_group_names)
    ignored_cube = ignored_cube_group_names()
    ignored_murmur = ignored_murmur_group_names()

    mapped_rows = []
    for murmur_group_name in mapped_names:
        reasons = []
        if selected_cube_group_name in ignored_cube:
            reasons.append('Cube group ignored')
        if murmur_group_name in ignored_murmur:
            reasons.append('Murmur group ignored')
        if murmur_group_name not in available_set:
            reasons.append('Missing on selected server')
        mapped_rows.append({
            'murmur_group_name': murmur_group_name,
            'suppressed': bool(reasons),
            'reason': '; '.join(reasons),
            'is_ignored': murmur_group_name in ignored_murmur,
        })

    available_rows = []
    for group_name in available_group_names:
        if group_name in mapped_name_set:
            continue
        reasons = []
        if group_name in ignored_murmur:
            reasons.append('Murmur group ignored')
        available_rows.append(
            {
                'murmur_group_name': group_name,
                'is_ignored': group_name in ignored_murmur,
                'suppressed': bool(reasons),
                'reason': '; '.join(reasons),
                'can_assign': not reasons,
            }
        )
    return available_rows, mapped_rows


@login_required
def group_mapping(request):
    if not _can_view_group_mapping(request.user):
        return HttpResponseForbidden()

    servers = [server for server in safe_list_servers() if server.is_active]
    selected_server = None
    selected_server_selector = str(request.GET.get('server', '') or '').strip()
    if servers:
        if selected_server_selector:
            selected_server = _resolve_server_from_selector(servers, selected_server_selector)
        if selected_server is None:
            selected_server = servers[0]

    selected_cube_group_name = str(request.GET.get('group', '') or '').strip()
    cube_group_names = all_cube_group_names()
    if selected_cube_group_name not in cube_group_names:
        selected_cube_group_name = cube_group_names[0] if cube_group_names else ''

    snapshot = None
    inventory_error = ''
    if selected_server is not None:
        snapshot, inventory_error = _load_inventory_snapshot(selected_server, refresh=False)

    inventory_groups = _inventory_group_names(snapshot)
    available_rows, mapped_rows = _mapping_rows(selected_cube_group_name, inventory_groups)
    cube_ignored = selected_cube_group_name in ignored_cube_group_names()
    divergence_rows = _divergence_rows(selected_server, snapshot, servers) if selected_server is not None else []

    return render(request, 'fg/group_mapping.html', {
        'servers': servers,
        'controls_tabs': _controls_tabs(request.user, 'groups'),
        'selected_server': selected_server,
        'selected_cube_group_name': selected_cube_group_name,
        'cube_group_names': cube_group_names,
        'cube_group_is_ignored': cube_ignored,
        'available_rows': available_rows,
        'mapped_rows': mapped_rows,
        'inventory_snapshot': snapshot,
        'inventory_error': inventory_error,
        'divergence_rows': divergence_rows,
        'can_change_group_mapping': _can_change_group_mapping(request.user),
    })


def _redirect_group_mapping(request):
    params = []
    server_selector = str(
        request.POST.get('server', '')
        or request.POST.get('server_key', '')
        or ''
    ).strip()
    group_name = str(request.POST.get('cube_group_name', '') or '').strip()
    if server_selector:
        params.append(f'server={server_selector}')
    if group_name:
        params.append(f'group={group_name}')
    suffix = f'?{"&".join(params)}' if params else ''
    return redirect(f'{reverse("mumble:group_mapping")}{suffix}')


@require_POST
@login_required
def group_mapping_refresh(request):
    if not _can_change_group_mapping(request.user):
        return HttpResponseForbidden()

    server_selector = str(
        request.POST.get('server', '')
        or request.POST.get('server_key', '')
        or ''
    ).strip()
    server = _resolve_server_from_selector(safe_list_servers(), server_selector)
    if server is not None:
        snapshot, error = _load_inventory_snapshot(server, refresh=True)
        if snapshot is not None and not error:
            messages.success(request, _('Murmur inventory refreshed from BG.'))
        else:
            messages.warning(request, _('Murmur inventory refresh failed: %(error)s') % {'error': error or 'unknown'})
    return _redirect_group_mapping(request)


@require_POST
@login_required
def group_mapping_add(request):
    if not _can_change_group_mapping(request.user):
        return HttpResponseForbidden()

    cube_group_name = str(request.POST.get('cube_group_name', '') or '').strip()
    murmur_group_name = str(request.POST.get('murmur_group_name', '') or '').strip()
    if cube_group_name and murmur_group_name:
        CubeGroupMapping.objects.get_or_create(
            cube_group_name=cube_group_name,
            murmur_group_name=murmur_group_name,
        )
        messages.success(request, _('Group mapping added.'))
    return _redirect_group_mapping(request)


@require_POST
@login_required
def group_mapping_remove(request):
    if not _can_change_group_mapping(request.user):
        return HttpResponseForbidden()

    cube_group_name = str(request.POST.get('cube_group_name', '') or '').strip()
    murmur_group_name = str(request.POST.get('murmur_group_name', '') or '').strip()
    CubeGroupMapping.objects.filter(
        cube_group_name=cube_group_name,
        murmur_group_name=murmur_group_name,
    ).delete()
    messages.success(request, _('Group mapping removed.'))
    return _redirect_group_mapping(request)


@require_POST
@login_required
def group_mapping_toggle_cube_ignore(request):
    if not _can_change_group_mapping(request.user):
        return HttpResponseForbidden()

    cube_group_name = str(request.POST.get('cube_group_name', '') or '').strip()
    existing = IgnoredCubeGroup.objects.filter(cube_group_name=cube_group_name).first()
    if existing is None:
        IgnoredCubeGroup.objects.create(cube_group_name=cube_group_name)
        messages.success(request, _('Cube group ignored.'))
    else:
        existing.delete()
        messages.success(request, _('Cube group restored.'))
    return _redirect_group_mapping(request)


@require_POST
@login_required
def group_mapping_toggle_murmur_ignore(request):
    if not _can_change_group_mapping(request.user):
        return HttpResponseForbidden()

    murmur_group_name = str(request.POST.get('murmur_group_name', '') or '').strip()
    existing = IgnoredMurmurGroup.objects.filter(murmur_group_name=murmur_group_name).first()
    if existing is None:
        IgnoredMurmurGroup.objects.create(murmur_group_name=murmur_group_name)
        messages.success(request, _('Murmur group ignored.'))
    else:
        existing.delete()
        messages.success(request, _('Murmur group restored.'))
    return _redirect_group_mapping(request)


@require_POST
@login_required
def group_mapping_cleanup_ignored(request):
    if not _can_change_group_mapping(request.user):
        return HttpResponseForbidden()

    ignored_cube = ignored_cube_group_names()
    ignored_murmur = ignored_murmur_group_names()
    deleted, _detail = CubeGroupMapping.objects.filter(
        cube_group_name__in=ignored_cube,
    ).delete()
    deleted2, _detail2 = CubeGroupMapping.objects.filter(
        murmur_group_name__in=ignored_murmur,
    ).delete()
    messages.success(
        request,
        _('Removed %(count)s ignored mapping row(s).') % {'count': int(deleted) + int(deleted2)},
    )
    return _redirect_group_mapping(request)


# ---------------------------------------------------------------------------
# Servers tab — which BG servers get a profile tile, and what it is called
# ---------------------------------------------------------------------------

def _server_panels_admin_bypass(user) -> bool:
    return bool(getattr(user, 'is_superuser', False))


def _has_server_panels_perm(user, codename: str) -> bool:
    return getattr(user, 'is_authenticated', False) and (
        _server_panels_admin_bypass(user)
        or user.has_perm(f'mumble_fg.{codename}')
    )


def _can_view_server_panels(user) -> bool:
    return _has_server_panels_perm(user, 'view_server_panels')


def _can_change_server_panels(user) -> bool:
    return _can_view_server_panels(user) and _has_server_panels_perm(user, 'change_server_panels')


def _server_panel_rows(servers, settings_by_key):
    """Table rows for the Servers tab: BG facts plus the tile overrides."""
    from fg.panels import get_profile_panel_provider

    provider = get_profile_panel_provider()
    rows = []
    for server in servers:
        server_key = str(getattr(server, 'server_key', '') or '').strip()
        row = settings_by_key.get(server_key)
        rows.append(
            {
                'server_key': server_key,
                'name': server.name,
                'address': server.address,
                'driver': _('ShitSpeak') if server.is_shitspeak else _('Murmur'),
                'bg_active': bool(server.is_active),
                'enabled': bool(row.enabled) if row is not None else True,
                'label': row.label if row is not None else '',
                'default_title': provider.default_panel_title_for(server),
                'effective_title': provider.panel_title_for(server, row),
            }
        )
    return rows


@login_required
def server_panels(request):
    if not _can_view_server_panels(request.user):
        return HttpResponseForbidden()

    servers = safe_list_servers()
    settings_by_key = ServerPanelSettings.by_server_key(
        getattr(server, 'server_key', '') for server in servers
    )

    return render(
        request,
        'fg/server_panels.html',
        {
            'controls_tabs': _controls_tabs(request.user, 'servers'),
            'server_rows': _server_panel_rows(servers, settings_by_key),
            'can_change_server_panels': _can_change_server_panels(request.user),
            'label_max_length': ServerPanelSettings._meta.get_field('label').max_length,
        },
    )


@require_POST
@login_required
def server_panels_save(request):
    if not _can_change_server_panels(request.user):
        return HttpResponseForbidden()

    # Only keys BG currently reports are writable, so a crafted POST cannot
    # seed settings rows for servers that do not exist.
    known_keys = {
        str(getattr(server, 'server_key', '') or '').strip()
        for server in safe_list_servers()
    }
    known_keys.discard('')
    if not known_keys:
        messages.error(request, _('No Mumble servers available from BG right now.'))
        return redirect('mumble:server_panels')

    max_length = ServerPanelSettings._meta.get_field('label').max_length
    saved = 0
    for server_key in request.POST.getlist('server_key'):
        server_key = str(server_key or '').strip()
        if server_key not in known_keys:
            continue
        ServerPanelSettings.objects.update_or_create(
            server_key=server_key,
            defaults={
                'enabled': f'enabled__{server_key}' in request.POST,
                'label': str(request.POST.get(f'label__{server_key}', '') or '').strip()[:max_length],
            },
        )
        saved += 1

    if saved:
        messages.success(
            request,
            _('Updated tile settings for %(count)s server(s).') % {'count': saved},
        )
    else:
        messages.error(request, _('No known Mumble servers were submitted.'))
    return redirect('mumble:server_panels')
