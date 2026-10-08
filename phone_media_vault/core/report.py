"""Self-contained Arabic (RTL) HTML reports for backups and verification.

HTML renders Arabic shaping/bidi correctly in every browser and can be printed
to PDF from the browser, so no PDF/font dependency is required.
"""

from __future__ import annotations

import html
import os
from datetime import datetime
from pathlib import Path

from .signer import atomic_write_bytes
from .verifier import VerificationReport


def human_size(size: int | float | None) -> str:
    if size is None:
        return "—"
    value = float(size)
    for unit in ("بايت", "ك.ب", "م.ب", "ج.ب", "ت.ب"):
        if value < 1024 or unit == "ت.ب":
            return f"{value:,.0f} {unit}" if unit == "بايت" else f"{value:,.2f} {unit}"
        value /= 1024
    return f"{value:,.2f} ت.ب"  # pragma: no cover


_STYLE = """
body{font-family:"Segoe UI",Tahoma,"Noto Naskh Arabic",Arial,sans-serif;margin:32px;color:#1f2937;background:#f8fafc}
h1{color:#0f766e;margin-bottom:4px}h2{margin-top:28px;border-bottom:2px solid #e2e8f0;padding-bottom:4px}
.badge{display:inline-block;padding:6px 14px;border-radius:999px;font-weight:700}
.ok{background:#dcfce7;color:#166534}.bad{background:#fee2e2;color:#991b1b}.warn{background:#fef9c3;color:#854d0e}
table{border-collapse:collapse;width:100%;background:#fff;margin-top:8px}
th,td{border:1px solid #e2e8f0;padding:6px 10px;text-align:right;vertical-align:top}
th{background:#f1f5f9}td.path{direction:ltr;text-align:left;font-family:Consolas,monospace;font-size:12px;word-break:break-all}
.meta td:first-child{width:220px;font-weight:600;background:#f8fafc}
footer{margin-top:32px;color:#64748b;font-size:12px}
@media print{body{background:#fff;margin:0}}
"""


def _row(label: str, value: object, *, ltr: bool = False) -> str:
    cls = ' class="path"' if ltr else ""
    return f"<tr><td>{html.escape(label)}</td><td{cls}>{html.escape(str(value))}</td></tr>"


def render_verification_report(report: VerificationReport, *, app_version: str = "") -> str:
    data = report.to_dict()
    device = data.get("device") or {}
    if report.complete:
        badge = '<span class="badge ok">✔ سليمة بالكامل</span>'
    elif report.intact:
        badge = '<span class="badge warn">⚠ سليمة مع ملفات لم تُنسخ</span>'
    else:
        badge = '<span class="badge bad">✖ توجد مشكلة</span>'

    rows = [
        _row("مجلد النسخة", data["backup_directory"], ltr=True),
        _row("تاريخ النسخة", data.get("backup_date") or "—"),
        _row("طراز الهاتف", device.get("model", "—")),
        _row("إصدار Android", device.get("android_version", "—")),
        _row("توقيع Ed25519", "صالح" if report.signature_valid else "غير صالح"),
        _row(
            "المفتاح العام",
            {True: "موثوق (يطابق مفتاح هذا الجهاز)", False: "غير موثوق", None: "لم يُفحص"}[
                report.public_key_trusted
            ],
        ),
        _row("إجمالي الملفات في manifest", data["files_total"]),
        _row("ملفات سليمة", data["ok_count"]),
        _row("ملفات تالفة/مفقودة", data["damaged_count"]),
        _row("ملفات لم تُنسخ", data["not_backed_up_count"]),
        _row("حجم الملفات السليمة", human_size(report.verified_bytes)),
        _row("ملفات إضافية غير موثقة", len(report.extra_files)),
        _row("ملفات .part متبقية", len(report.leftover_part_files)),
    ]

    problems = "".join(
        "<tr><td class=\"path\">{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(check.phone_path), html.escape(check.status_ar), html.escape(check.detail or "")
        )
        for check in report.problem_checks
    )
    problems_html = (
        f"<h2>الملفات التي بها مشكلة ({len(report.problem_checks)})</h2>"
        f"<table><tr><th>مسار الهاتف</th><th>الحالة</th><th>تفاصيل</th></tr>{problems}</table>"
        if problems
        else "<h2>الملفات</h2><p>جميع الملفات الموثقة سليمة.</p>"
    )
    extras = "".join(f'<tr><td class="path">{html.escape(p)}</td></tr>' for p in report.extra_files[:500])
    extras_html = (
        f"<h2>ملفات إضافية غير موجودة في manifest</h2><table>{extras}</table>" if extras else ""
    )
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>تقرير التحقق — خزنة الوسائط</title><style>{_STYLE}</style></head>
<body>
<h1>تقرير التحقق من سلامة النسخة الاحتياطية</h1>
<p>{badge} &nbsp; {html.escape(report.verdict_ar)}</p>
<h2>الملخص</h2><table class="meta">{''.join(rows)}</table>
{problems_html}
{extras_html}
<footer>أُنشئ بواسطة خزنة الوسائط (Phone Media Vault) {html.escape(app_version)} — {generated}</footer>
</body></html>
"""


def write_verification_report(
    report: VerificationReport,
    output_path: str | os.PathLike[str] | None = None,
    *,
    app_version: str = "",
) -> Path:
    target = Path(output_path) if output_path else report.backup_directory / "verification_report.html"
    atomic_write_bytes(target, render_verification_report(report, app_version=app_version).encode("utf-8"))
    return target
