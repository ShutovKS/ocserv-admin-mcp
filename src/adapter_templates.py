# FILE: src/adapter_templates.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Render and synchronize managed ocserv configuration templates for main config and policy groups.
#   SCOPE: Template rendering, default template generation, managed file synchronization.
#   DEPENDS: M-OCSERV-ADAPTER
#   LINKS: M-ADAPTER-TEMPLATES
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   render_managed_files - Render all managed config files from templates.
#   template_paths - List all template file paths.
#   sync_managed_files - Synchronize managed files for a given action scope.
#   ensure_default_templates - Ensure default templates exist for planned groups.
# END_MODULE_MAP

from __future__ import annotations

from pathlib import Path
from string import Template
from typing import Any

import src.ocserv_adapter as _oa


def _default_main_template(paths: _oa.OcservPaths) -> str:
    return (
        "# managed by ocserv-admin\n"
        "# render actual deployment directives through the template file\n"
        f"# group config dir: {_oa._resolved_group_config_dir(paths)}\n"
    )


def _default_group_template(group: str) -> str:
    return (
        f"# {group}\n"
        "# managed by ocserv-admin\n"
        "# add group-specific directives here\n"
    )


def _render_template(template_path: Path, variables: dict[str, str], fallback: str) -> str:
    if template_path.exists():
        template_text = template_path.read_text(encoding="utf-8")
    else:
        template_text = fallback
    return Template(template_text).safe_substitute(variables)


def ensure_default_templates(paths: _oa.OcservPaths, template_path_list: list[Path] | None = None) -> list[str]:
    group_template_dir = _oa._resolved_group_template_dir(paths)
    if not group_template_dir.exists():
        group_template_dir.mkdir(parents=True, exist_ok=True)
    main_template = _oa._resolved_main_template(paths)
    created: list[str] = []
    candidates = template_path_list if template_path_list is not None else [main_template] + [group_template_dir / f"{group}.conf.tpl" for group in _oa._planned_group_names(paths)]
    for path in candidates:
        if path.exists():
            continue
        if path == main_template:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_default_main_template(paths), encoding="utf-8")
            created.append(str(path))
        elif path.parent == group_template_dir and (path.name.endswith(".conf.tpl") or path.name.endswith(".tpl")):
            name = path.name
            group = name[: -len(".conf.tpl")] if name.endswith(".conf.tpl") else path.stem
            path.write_text(_default_group_template(group), encoding="utf-8")
            created.append(str(path))
    return created


def render_managed_files(paths: _oa.OcservPaths) -> dict[Path, str]:
    rendered: dict[Path, str] = {}
    group_config_dir = _oa._resolved_group_config_dir(paths)
    main_config = _oa._resolved_main_config_file(paths)
    rendered[main_config] = _render_template(
        _oa._resolved_main_template(paths),
        {"GROUP_CONFIG_DIR": str(group_config_dir)},
        _default_main_template(paths),
    )

    for group in _oa._planned_group_names(paths):
        template_path = _oa._resolved_group_template_dir(paths) / f"{group}.conf.tpl"
        rendered[_oa._group_config_path(paths, group)] = _render_template(
            template_path,
            {
                "GROUP_NAME": group,
                "GROUP_CONFIG_FILE": str(_oa._group_config_path(paths, group)),
                "GROUP_CONFIG_DIR": str(group_config_dir),
            },
            _default_group_template(group),
        )
    for user in _oa._load_user_payload(paths).values():
        ipv4_address = user.get("ipv4_address")
        username = user.get("username")
        if isinstance(username, str) and isinstance(ipv4_address, str) and ipv4_address:
            rendered[_oa._user_config_path(paths, username)] = _oa._render_user_config(ipv4_address)
    return rendered


def template_paths(paths: _oa.OcservPaths) -> list[Path]:
    return [_oa._resolved_main_template(paths), *[_oa._resolved_group_template_dir(paths) / f"{group}.conf.tpl" for group in _oa._planned_group_names(paths)]]


def _planned_mutation_paths(paths: _oa.OcservPaths, action: str, group: str | None = None, username: str | None = None) -> list[Path]:
    planned: list[Path] = []
    if action in {"create_user", "assign_group"}:
        planned.extend([
            _oa._resolved_main_template(paths),
            _oa._resolved_main_config_file(paths),
        ])
        if group is not None:
            planned.extend([
                _oa._resolved_group_template_dir(paths) / f"{group}.conf.tpl",
                _oa._group_config_path(paths, group),
            ])
    if action in {"create_user", "update_user_ip", "delete_user"} and username is not None:
        planned.append(_oa._user_config_path(paths, username))
    planned.append(paths.users_file)
    if action in {"create_user", "assign_group", "delete_user", "update_user_ip"}:
        planned.append(_oa._resolved_user_group_map_file(paths))
    return sorted(set(planned))


def _managed_paths(paths: _oa.OcservPaths) -> list[Path]:
    rendered = render_managed_files(paths)
    managed = set(rendered)
    managed.add(paths.users_file)
    managed.add(_oa._resolved_user_group_map_file(paths))
    managed.update(template_paths(paths))
    return sorted(managed)


def sync_managed_files(paths: _oa.OcservPaths, action: str, group: str | None = None) -> dict[str, Any]:
    relevant_paths = set(_planned_mutation_paths(paths, action, group))
    relevant_templates = {path for path in relevant_paths if path.suffix == ".tpl"}
    template_changes = ensure_default_templates(paths, list(relevant_templates))
    rendered = render_managed_files(paths)
    changed_files: list[str] = []
    for file_path, content in rendered.items():
        if file_path not in relevant_paths:
            continue
        file_path.parent.mkdir(parents=True, exist_ok=True)
        existing = file_path.read_text(encoding="utf-8") if file_path.exists() else None
        normalized = content if content.endswith("\n") else content + "\n"
        if existing != normalized:
            file_path.write_text(normalized, encoding="utf-8")
            changed_files.append(str(file_path))
    return {
        "changed_files": sorted(set(changed_files) | set(template_changes)),
        "rendered_files": sorted(str(path) for path in rendered if path in relevant_paths),
        "template_files": sorted(str(path) for path in relevant_templates),
    }
