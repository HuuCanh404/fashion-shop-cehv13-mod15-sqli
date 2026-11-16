#!/usr/bin/env python3
"""
verify_admin_security.py - End-to-end verification of Fashion-Shop Admin Security & Defense Triad
Verifies:
1. Admin authentication guard (302 redirect when unauthenticated in hardened mode)
2. Hardened admin_login.php + Step-up 6-digit OTP verification flow
3. Admin Security Dashboard (security_dashboard.php) rendering & sandbox controls
4. Layer 3 Deceptive HTTP 200 OK response & fake export downloads (.sql/.csv/.json) against SQLi signatures
5. Layer 2 Sliding-window rate limiting (200 requests / 60s -> 600s cooldown, CF-Connecting-IP aware)
6. Toggleable Vulnerable Lab mode on Admin endpoints (restored back to hardened afterward)
"""

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar

BASE_URL = "http://127.0.0.1:8080/shopweb"
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFENSE_CFG_PATH = os.path.join(ROOT_DIR, "fashion-shop", "database", "defense_config.json")
OTP_LOG_PATH = os.path.join(ROOT_DIR, "fashion-shop", "quantri", "logs", "otp_mailbox.log")
OUTPUT_JSON = os.path.join(ROOT_DIR, "tests", "admin_security_verification.json")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener(follow_redirects=False):
    cj = http.cookiejar.CookieJar()
    if follow_redirects:
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj)), cj
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect), cj


def send_req(opener, url, method="GET", data=None, headers=None):
    hdrs = dict(headers or {})
    encoded = urllib.parse.urlencode(data).encode("utf-8") if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=encoded, headers=hdrs, method=method)
    t0 = time.time()
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace"), round(time.time() - t0, 4)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, dict(e.headers), body, round(time.time() - t0, 4)


def run_all():
    with open(DEFENSE_CFG_PATH, "r", encoding="utf-8") as f:
        orig_cfg = json.load(f)

    results = []
    try:
        # Ensure hardened default config
        hardened_cfg = {
            "lab_mode": "hardened",
            "enforce_admin_auth": True,
            "rate_limit_enabled": True,
            "rate_limit_window_sec": 60,
            "rate_limit_max_requests": 200,
            "rate_limit_cooldown_sec": 600,
            "otp_enabled": True,
            "deception_enabled": True,
            "cloudflare_mode": True,
        }
        with open(DEFENSE_CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(hardened_cfg, f, indent=2)

        # 1. Auth guard redirect when unauthenticated
        opener_no_redir, _ = make_opener(follow_redirects=False)
        status, hdrs, _, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/quantri/security_dashboard.php",
            headers={"CF-Connecting-IP": "198.51.100.10"},
        )
        loc = hdrs.get("Location", "")
        results.append({
            "test": "Admin Auth Guard blocks unauthenticated access (Hardened)",
            "passed": status == 302 and "admin_login.php" in loc,
            "status": status,
            "location": loc,
        })

        # 2. Hardened admin_login + OTP step-up verification
        opener_auth, _ = make_opener(follow_redirects=True)
        login_headers = {"CF-Connecting-IP": "198.51.100.11"}
        s_login, _, b_login, _ = send_req(
            opener_auth,
            f"{BASE_URL}/quantri/admin_login.php?mode=hardened",
            method="POST",
            data={"username": "admin_demo", "password": "Admin@123"},
            headers=login_headers,
        )
        otp_prompted = "OTP" in b_login
        latest_otp = None
        if os.path.exists(OTP_LOG_PATH):
            with open(OTP_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                lines = [ln.strip() for ln in f if "admin_demo" in ln and "OTP" in ln]
                if lines:
                    m = re.search(r"OTP xác minh:\s*(\d{6})", lines[-1])
                    if m:
                        latest_otp = m.group(1)

        otp_ok = False
        dash_ok = False
        if latest_otp:
            s_otp, _, b_otp, _ = send_req(
                opener_auth,
                f"{BASE_URL}/quantri/admin_login.php?mode=hardened",
                method="POST",
                data={"action": "verify_otp", "otp_code": latest_otp},
                headers=login_headers,
            )
            dash_ok = s_otp == 200 and "Trung tâm Quản lý An ninh" in b_otp
            otp_ok = dash_ok

        results.append({
            "test": "Hardened Admin Login + Step-up 6-digit OTP Flow",
            "passed": s_login == 200 and otp_prompted and bool(latest_otp) and otp_ok,
            "otp_prompted": otp_prompted,
            "otp_issued": bool(latest_otp),
            "dashboard_reached": dash_ok,
        })

        # 3. Admin Sandbox CSRF + Deceptive HTTP 200 check inside security_dashboard.php
        s_dash, _, b_dash, _ = send_req(
            opener_auth,
            f"{BASE_URL}/quantri/security_dashboard.php",
            headers=login_headers,
        )
        csrf_m = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', b_dash)
        sandbox_decoy_ok = False
        if csrf_m:
            csrf = csrf_m.group(1)
            s_sb, _, b_sb, _ = send_req(
                opener_auth,
                f"{BASE_URL}/quantri/security_dashboard.php",
                method="POST",
                data={"csrf_token": csrf, "action": "run_sandbox", "sandbox_term": "' UNION SELECT 1,2,3,4 -- "},
                headers=login_headers,
            )
            sandbox_decoy_ok = s_sb == 200 and "Nghi binh HTTP 200 OK" in b_sb

        results.append({
            "test": "Admin Security Dashboard Sandbox & Deceptive 200 Preview",
            "passed": s_dash == 200 and sandbox_decoy_ok,
            "dashboard_status": s_dash,
            "sandbox_decoy_ok": sandbox_decoy_ok,
        })

        # 4. Layer 3 Deceptive HTTP 200 OK on public/admin endpoint probe + Fake Export Downloads
        s_dec, hdr_dec, b_dec, elapsed_dec = send_req(
            opener_no_redir,
            f"{BASE_URL}/quantri/editsp.php?id=" + urllib.parse.quote("1 UNION SELECT 1,2,3 -- "),
            headers={"CF-Connecting-IP": "198.51.100.22"},
        )
        decoy_hdr = hdr_dec.get("X-Protection-System", "") == "Deceptive-Decoy-Active"
        decoy_ui_ok = (
            "sys_export=sql" in b_dec
            and "sys_export=csv" in b_dec
            and "sys_export=json" in b_dec
            and "shopdb" in b_dec
        )
        s_dl_sql, h_dl_sql, b_dl_sql, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/quantri/editsp.php?sys_export=sql",
            headers={"CF-Connecting-IP": "198.51.100.22"},
        )
        s_dl_csv, h_dl_csv, b_dl_csv, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/quantri/editsp.php?sys_export=csv",
            headers={"CF-Connecting-IP": "198.51.100.22"},
        )
        s_dl_json, h_dl_json, b_dl_json, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/quantri/editsp.php?sys_export=json",
            headers={"CF-Connecting-IP": "198.51.100.22"},
        )
        exports_ok = (
            s_dl_sql == 200 and "attachment" in h_dl_sql.get("Content-Disposition", "") and "INSERT INTO `users`" in b_dl_sql
            and s_dl_csv == 200 and "attachment" in h_dl_csv.get("Content-Disposition", "") and "password_hash" in b_dl_csv
            and s_dl_json == 200 and "attachment" in h_dl_json.get("Content-Disposition", "") and "system_config" in b_dl_json
        )
        results.append({
            "test": "Layer 3 Deceptive HTTP 200 OK Neutralization & Fake Export Trap (CF-Connecting-IP)",
            "passed": s_dec == 200 and decoy_hdr and decoy_ui_ok and exports_ok and "SQL Error" not in b_dec,
            "status": s_dec,
            "decoy_header": decoy_hdr,
            "decoy_ui_ok": decoy_ui_ok,
            "exports_ok": exports_ok,
            "elapsed_sec": elapsed_dec,
        })

        # 5. Layer 2 Rate Limit: 200 requests allowed in 60s, 201st returns HTTP 429 with Retry-After: 600
        test_ip = f"203.0.113.{int(time.time()) % 200 + 10}"
        statuses = []
        retry_after = None
        for i in range(201):
            st, h, _, _ = send_req(
                opener_no_redir,
                f"{BASE_URL}/quantri/admin_login.php?mode=hardened&n={i}",
                headers={"CF-Connecting-IP": test_ip, "Accept": "application/json"},
            )
            statuses.append(st)
            if st == 429:
                retry_after = int(h.get("Retry-After", "0"))
        rl_passed = all(s == 200 for s in statuses[:200]) and statuses[200] == 429 and (590 <= (retry_after or 0) <= 600)
        results.append({
            "test": "Layer 2 Sliding-Window Rate Limit (200 req/60s -> 600s block)",
            "passed": rl_passed,
            "allowed_first_200": sum(1 for s in statuses[:200] if s == 200),
            "status_201st": statuses[200] if len(statuses) > 200 else None,
            "retry_after": retry_after,
        })

        # 6. Vulnerable Lab Mode check on admin_management.php & editsp.php (no auth + raw SQL demo)
        vuln_cfg = dict(hardened_cfg)
        vuln_cfg["lab_mode"] = "vulnerable"
        vuln_cfg["enforce_admin_auth"] = False
        with open(DEFENSE_CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(vuln_cfg, f, indent=2)

        s_v_adm, _, b_v_adm, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/quantri/user_management/admin_management.php?search=" + urllib.parse.quote("Huyền"),
            headers={"CF-Connecting-IP": "198.51.100.99"},
        )
        vuln_ok = s_v_adm == 200 and "VULNERABLE LAB" in b_v_adm and "Huyền" in b_v_adm
        results.append({
            "test": "Vulnerable Lab Mode (Admin Unauthenticated + Unparameterized Search Demo)",
            "passed": vuln_ok,
            "status": s_v_adm,
        })

        # 7. Storefront pages (index.php & product_detail.php) + Hardened parameterized resistance
        with open(DEFENSE_CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(hardened_cfg, f, indent=2)
        s_home, _, b_home, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/index.php",
            headers={"CF-Connecting-IP": "198.51.100.120"},
        )
        s_pd, _, b_pd, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/fontend/product_detail.php?id=3",
            headers={"CF-Connecting-IP": "198.51.100.120"},
        )
        s_pd_probe, h_pd_probe, b_pd_probe, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/fontend/product_detail.php?id=" + urllib.parse.quote("3 UNION SELECT 1,2,3-- "),
            headers={"CF-Connecting-IP": "198.51.100.121"},
        )
        sf_ok = (
            s_home == 200
            and s_pd == 200
            and s_pd_probe == 200
            and h_pd_probe.get("X-Protection-System") == "Deceptive-Decoy-Active"
            and "Warning" not in b_home
            and "Fatal error" not in b_pd
        )
        results.append({
            "test": "Storefront Availability & Hardened Parameter/Decoy Protection (index + product_detail)",
            "passed": sf_ok,
            "home_status": s_home,
            "product_detail_status": s_pd,
            "probe_header": h_pd_probe.get("X-Protection-System", ""),
        })

        # 8. Vulnerable Admin Login Demo redirects straight to /quantri/index.php with no decoy when ?mode=vulnerable
        with open(DEFENSE_CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(vuln_cfg, f, indent=2)
        s_al_v, h_al_v, _, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/quantri/admin_login.php?mode=vulnerable",
            method="POST",
            data={"username": "' OR '1'='1' #", "password": "x"},
            headers={"CF-Connecting-IP": "198.51.100.122"},
        )
        al_loc = h_al_v.get("Location", "")
        al_vuln_ok = (
            s_al_v == 302
            and "/quantri/index.php" in al_loc
            and h_al_v.get("X-Protection-System", "") == ""
        )
        results.append({
            "test": "Admin Login Vulnerable Lab Demonstration Flow",
            "passed": al_vuln_ok,
            "status": s_al_v,
            "location": al_loc,
        })

        # 9. User Login -> Admin Escalation in Vulnerable Lab Mode (SQLi & Storefront Search)
        with open(DEFENSE_CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(vuln_cfg, f, indent=2)
        opener_u2a, _ = make_opener(follow_redirects=False)
        s_u2a, h_u2a, _, _ = send_req(
            opener_u2a,
            f"{BASE_URL}/xacthuc/login.php",
            method="POST",
            data={"username": "' OR role='admin' #", "password": "x"},
            headers={"CF-Connecting-IP": "198.51.100.130"},
        )
        u2a_redir = h_u2a.get("Location", "")
        s_sr_v, _, b_sr_v, _ = send_req(
            opener_u2a,
            f"{BASE_URL}/fontend/search_results.php?q=ao",
            headers={"CF-Connecting-IP": "198.51.100.131"},
        )
        results.append({
            "test": "Vulnerable User Login -> Admin Privilege Escalation & Storefront Search Lab",
            "passed": s_u2a == 302 and "/quantri/index.php" in u2a_redir and s_sr_v == 200 and "VULNERABLE LAB" in b_sr_v,
            "login_status": s_u2a,
            "redirect_location": u2a_redir,
            "search_status": s_sr_v,
        })

        # 10. Hardened User Login blocks Forged Cookie, Direct Admin Portal Escalation & Protects Storefront Search
        with open(DEFENSE_CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(hardened_cfg, f, indent=2)
        opener_cookie_forged, _ = make_opener(follow_redirects=False)
        send_req(
            opener_cookie_forged,
            f"{BASE_URL}/xacthuc/login.php",
            headers={"CF-Connecting-IP": "198.51.100.132", "Cookie": "remember_user=admin_demo"},
        )
        s_after_cookie, h_after_cookie, _, _ = send_req(
            opener_cookie_forged,
            f"{BASE_URL}/quantri/index.php",
            headers={"CF-Connecting-IP": "198.51.100.132", "Cookie": "remember_user=admin_demo"},
        )
        cookie_blocked = s_after_cookie == 302 and "admin_login.php" in h_after_cookie.get("Location", "")

        opener_u_hard, _ = make_opener(follow_redirects=False)
        _, _, b_u_get, _ = send_req(
            opener_u_hard,
            f"{BASE_URL}/xacthuc/login.php",
            headers={"CF-Connecting-IP": "198.51.100.133"},
        )
        no_admin_link = ("/quantri/admin_login.php" not in b_u_get) and ("Cổng Quản trị Admin" not in b_u_get)
        u_csrf_m = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', b_u_get)
        u_csrf = u_csrf_m.group(1) if u_csrf_m else ""
        s_u_adm_blk, _, b_u_adm_blk, _ = send_req(
            opener_u_hard,
            f"{BASE_URL}/xacthuc/login.php",
            method="POST",
            data={"csrf_token": u_csrf, "username": "admin_demo", "password": "Admin@123"},
            headers={"CF-Connecting-IP": "198.51.100.133"},
        )
        admin_portal_blocked = (
            s_u_adm_blk == 200
            and "Cổng Admin riêng" in b_u_adm_blk
            and "/quantri/admin_login.php" not in b_u_adm_blk
        )

        # Verify deception HTTP 200 triggers on User Login SQLi ONLY when protection is active
        _, h_u_decoy, _, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/xacthuc/login.php",
            method="POST",
            data={"csrf_token": u_csrf, "username": "' OR role='admin' #", "password": "x"},
            headers={"CF-Connecting-IP": "198.51.100.136"},
        )
        user_sqli_decoy_ok = h_u_decoy.get("X-Protection-System") == "Deceptive-Decoy-Active"

        s_sr_ok, _, b_sr_ok, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/fontend/search_results.php?q=ao",
            headers={"CF-Connecting-IP": "198.51.100.134"},
        )
        s_sr_decoy, h_sr_decoy, _, _ = send_req(
            opener_no_redir,
            f"{BASE_URL}/fontend/search_results.php?q=" + urllib.parse.quote("' UNION SELECT 1,2,3 -- "),
            headers={"CF-Connecting-IP": "198.51.100.135"},
        )
        results.append({
            "test": "Hardened User Portal (Signed Cookie, Role Separation & Storefront Search Defense)",
            "passed": cookie_blocked and no_admin_link and admin_portal_blocked and user_sqli_decoy_ok and s_sr_ok == 200 and "Deprecated" not in b_sr_ok and h_sr_decoy.get("X-Protection-System") == "Deceptive-Decoy-Active",
            "cookie_blocked": cookie_blocked,
            "no_admin_link": no_admin_link,
            "admin_portal_blocked": admin_portal_blocked,
            "user_sqli_decoy_ok": user_sqli_decoy_ok,
            "search_ok": s_sr_ok,
            "search_decoy_header": h_sr_decoy.get("X-Protection-System", ""),
        })
    finally:
        with open(DEFENSE_CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(orig_cfg, f, indent=2)

    all_passed = all(r["passed"] for r in results)
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "passed_count": sum(1 for r in results if r["passed"]),
        "total_count": len(results),
        "all_passed": all_passed,
        "results": results,
    }
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    run_all()
