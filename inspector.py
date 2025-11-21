#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
APK Diff Inspector
inspector.py

Сравнение двух APK-файлов по метаданным, разрешениям, компонентам, фичам и размерам.
Генерация diff-отчёта + секция security.

Если установлен androguard — используется для парсинга AndroidManifest.xml.
"""

import argparse
import zipfile
import json
import sys
import os
import shutil
from pathlib import Path

# ================================================================
# Опциональная интеграция ANDROGUARD (если есть)
# ================================================================

USE_ANDROGUARD = False
try:
    from androguard.core.bytecodes.apk import APK
    USE_ANDROGUARD = True
except ImportError:
    pass


# ================================================================
# Утилиты
# ================================================================

def human_size(num):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


def read_manifest_with_androguard(path):
    """Парсер на базе androguard — идеальный вариант, если библиотека установлена."""
    apk = APK(path)
    meta = {
        "package": apk.package,
        "versionName": apk.version_name,
        "versionCode": apk.version_code,
        "minSdk": apk.get_min_sdk_version(),
        "targetSdk": apk.get_target_sdk_version(),
    }

    permissions = list(apk.get_permissions())

    components = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }

    for a in apk.get_activities():
        components["activities"].append({
            "name": a,
            "exported": apk.get_activity_exported(a),
            "has_intent_filter": len(apk.get_intent_filters("activity", a)) > 0
        })

    for s in apk.get_services():
        components["services"].append({
            "name": s,
            "exported": apk.get_service_exported(s),
        })

    for r in apk.get_receivers():
        components["receivers"].append({
            "name": r,
            "exported": apk.get_receiver_exported(r),
        })

    for p in apk.get_providers():
        components["providers"].append({
            "name": p,
            "exported": apk.get_provider_exported(p),
        })

    features = apk.get_features()

    return meta, permissions, components, features


def fallback_manifest_info():
    """Если androguard отсутствует — возвращаем пустые структуры (MVP)."""
    return (
        {
            "package": None,
            "versionName": None,
            "versionCode": None,
            "minSdk": None,
            "targetSdk": None,
        },
        [],
        {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        },
        []
    )


# ================================================================
# Чтение данных из APK
# ================================================================

def collect_sizes(path):
    """Сбор информации о размерах файлов внутри APK."""
    sizes = {
        "apk_size": os.path.getsize(path),
        "dex_total": 0,
        "dex_count": 0,
        "lib_total": 0,
        "res_total": 0,
        "assets_total": 0,
        "abis": set()
    }

    with zipfile.ZipFile(path, "r") as z:
        for info in z.infolist():
            fn = info.filename

            if fn.startswith("classes") and fn.endswith(".dex"):
                sizes["dex_total"] += info.file_size
                sizes["dex_count"] += 1

            elif fn.startswith("lib/") and "/" in fn:
                sizes["lib_total"] += info.file_size
                abi = fn.split("/")[1]
                sizes["abis"].add(abi)

            elif fn.startswith("res/"):
                sizes["res_total"] += info.file_size

            elif fn.startswith("assets/"):
                sizes["assets_total"] += info.file_size

    sizes["abis"] = sorted(sizes["abis"])
    return sizes


def load_apk_info(path):
    """Структурированная загрузка информации об APK."""
    sizes = collect_sizes(path)

    # Попытка использовать Androguard
    if USE_ANDROGUARD:
        try:
            meta, permissions, components, features = read_manifest_with_androguard(path)
            return {
                "meta": meta,
                "permissions": permissions,
                "components": components,
                "features": features,
                "sizes": sizes
            }
        except Exception as e:
            print(f"[WARNING] Ошибка работы androguard: {e}")
    
    # fallback-режим (без манифеста)
    meta, permissions, components, features = fallback_manifest_info()
    return {
        "meta": meta,
        "permissions": permissions,
        "components": components,
        "features": features,
        "sizes": sizes
    }


# ================================================================
# DIFF (по секциям)
# ================================================================

def diff_simple_values(old, new):
    diff = {}
    for key in old.keys():
        if old[key] != new[key]:
            diff[key] = {"old": old[key], "new": new[key]}
    return diff


def diff_permissions(old_list, new_list):
    old = set(old_list)
    new = set(new_list)
    return {
        "added": sorted(list(new - old)),
        "removed": sorted(list(old - new)),
        "unchanged": sorted(list(old & new))
    }


def diff_components(old_c, new_c):
    res = {}
    for comp_type in ["activities", "services", "receivers", "providers"]:
        old = {x["name"]: x for x in old_c[comp_type]}
        new = {x["name"]: x for x in new_c[comp_type]}

        added = [new[k] for k in new.keys() - old.keys()]
        removed = [old[k] for k in old.keys() - new.keys()]
        changed = []

        for name in new.keys() & old.keys():
            if new[name] != old[name]:
                changed.append({"old": old[name], "new": new[name]})

        res[comp_type] = {
            "added": added,
            "removed": removed,
            "changed": changed
        }

    return res


def diff_features(old_list, new_list):
    old = set(old_list)
    new = set(new_list)
    return {
        "added": sorted(list(new - old)),
        "removed": sorted(list(old - new)),
        "unchanged": sorted(list(old & new))
    }


def diff_sizes(old, new):
    diff = {}
    for key in ["apk_size", "dex_total", "lib_total", "res_total", "assets_total"]:
        if old[key] != new[key]:
            diff[key] = {"old": old[key], "new": new[key]}

    if old["abis"] != new["abis"]:
        diff["abis"] = {"old": old["abis"], "new": new["abis"]}

    return diff


# ================================================================
# SECURITY АНАЛИЗ
# ================================================================

DANGEROUS_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_SMS",
    "android.permission.WRITE_SMS",
    "android.permission.READ_PHONE_STATE",
}

def build_security_report(diff):
    alerts = []

    # Dangerous permissions added
    for p in diff["permissions"]["added"]:
        if p in DANGEROUS_PERMISSIONS:
            alerts.append({
                "level": "high",
                "type": "permission",
                "message": f"New dangerous permission: {p}"
            })

    # Exported=true changes
    comps = diff["components"]
    for comp_type in comps:
        for ch in comps[comp_type]["changed"]:
            old, new = ch["old"], ch["new"]
            if old.get("exported") is False and new.get("exported") is True:
                alerts.append({
                    "level": "high",
                    "type": "component",
                    "message": f"{comp_type[:-1].title()} exported changed: {old['name']} (false -> true)"
                })

        for added in comps[comp_type]["added"]:
            if added.get("exported") is True:
                alerts.append({
                    "level": "high",
                    "type": "component",
                    "message": f"New exported {comp_type[:-1]}: {added['name']}"
                })

    return alerts


# ================================================================
# ФОРМАТИРОВАНИЕ ВЫВОДА
# ================================================================

def print_console_report(diff, security, no_color=False):
    C = {
        "green": "" if no_color else "\033[92m",
        "red": "" if no_color else "\033[91m",
        "yellow": "" if no_color else "\033[93m",
        "reset": "" if no_color else "\033[0m"
    }

    print("=== APK Inspector Report ===\n")

    # Meta
    print("[Meta]")
    for k, v in diff["meta"].items():
        print(f"- {k}: {v['old']} -> {v['new']}")
    print()

    # Permissions
    print("[Permissions]")
    for p in diff["permissions"]["added"]:
        print(f"{C['green']}+ {p}{C['reset']}")
    for p in diff["permissions"]["removed"]:
        print(f"{C['red']}- {p}{C['reset']}")
    print()

    # Components
    print("[Components]")
    for comp in diff["components"]:
        print(f"  {comp.capitalize()}:")
        for a in diff["components"][comp]["added"]:
            print(f"    {C['green']}+ {a['name']}{C['reset']}")
        for r in diff["components"][comp]["removed"]:
            print(f"    {C['red']}- {r['name']}{C['reset']}")
        for ch in diff["components"][comp]["changed"]:
            print(f"    {C['yellow']}~ {ch['old']['name']}{C['reset']}")
    print()

    # Features
    print("[Features]")
    for f in diff["features"]["added"]:
        print(f"{C['green']}+ {f}{C['reset']}")
    for f in diff["features"]["removed"]:
        print(f"{C['red']}- {f}{C['reset']}")
    print()

    # Sizes
    print("[Sizes]")
    for k, v in diff["sizes"].items():
        print(f"- {k}: {human_size(v['old'])} -> {human_size(v['new'])}")
    print()

    # Security
    print("[Security]")
    for alert in security:
        level = alert["level"].upper()
        color = C["red"] if level == "HIGH" else C["yellow"]
        print(f"{color}! {level}: {alert['message']}{C['reset']}")
    print()


# ================================================================
# MAIN
# ================================================================

def main():
    parser = argparse.ArgumentParser(description="APK Diff Inspector")
    parser.add_argument("old_apk")
    parser.add_argument("new_apk")
    parser.add_argument("--json", action="store_true", help="Вывести отчёт в формате JSON")
    parser.add_argument("-o", "--output", help="Файл для сохранения отчёта")
    parser.add_argument("--no-color", action="store_true", help="Отключить цветной вывод")
    parser.add_argument("--danger-only", action="store_true", help="Показать только security")
    args = parser.parse_args()

    old_path = args.old_apk
    new_path = args.new_apk

    if not Path(old_path).exists():
        print("ERROR: old.apk не найден")
        sys.exit(1)
    if not Path(new_path).exists():
        print("ERROR: new.apk не найден")
        sys.exit(1)

    # Загрузка инфы
    old_info = load_apk_info(old_path)
    new_info = load_apk_info(new_path)

    # DIFF
    diff = {
        "meta": diff_simple_values(old_info["meta"], new_info["meta"]),
        "permissions": diff_permissions(old_info["permissions"], new_info["permissions"]),
        "components": diff_components(old_info["components"], new_info["components"]),
        "features": diff_features(old_info["features"], new_info["features"]),
        "sizes": diff_sizes(old_info["sizes"], new_info["sizes"])
    }

    security = build_security_report(diff)

    # JSON вывод
    if args.json:
        print(json.dumps({"diff": diff, "security": security}, indent=2, ensure_ascii=False))
        return

    # danger-only
    if args.danger_only:
        for alert in security:
            print(f"{alert['level'].upper()}: {alert['message']}")
        return

    # Консольный вывод
    print_console_report(diff, security, no_color=args.no_color)

    # Файл
    if args.output:
        ext = args.output.lower()
        if ext.endswith(".json"):
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump({"diff": diff, "security": security}, f, indent=2, ensure_ascii=False)
            print(f"JSON отчёт сохранён в {args.output}")
        else:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json.dumps({"diff": diff, "security": security}, indent=2, ensure_ascii=False))
            print(f"Отчёт сохранён в {args.output}")


if __name__ == "__main__":
    main()