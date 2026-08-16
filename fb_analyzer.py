#!/usr/bin/env python3
"""تحليل تعليقات منشور فيسبوك باستخدام Facebook Graph API.

مهم: هذا السكربت يقدم heuristic لا يثبت هوية صاحب الحساب. توفر بيانات المستخدمين
يتوقف على نوع المنشور والتوكن والصلاحيات التي تمنحها Meta للتطبيق.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import matplotlib.pyplot as plt
import pandas as pd
import requests
from dotenv import load_dotenv

API_VERSION = "v18.0"
API_BASE = f"https://graph.facebook.com/{API_VERSION}"
DEFAULT_DELAY = 0.35
REQUEST_TIMEOUT = 30
SUSPICIOUS_URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s]+", re.IGNORECASE
)
SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click")

logger = logging.getLogger("fb_analyzer")


def configure_logging(log_path: Path) -> None:
    """تهيئة التسجيل في الطرفية وملف الأخطاء، مع إخفاء التوكن من الرسائل."""
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def extract_post_id(value: str) -> str:
    """استخراج post_id من أشهر صيغ روابط منشورات فيسبوك."""
    value = value.strip()
    if value.isdigit():
        return value
    parsed = urlparse(value if "://" in value else f"https://{value}")
    query = parse_qs(parsed.query)
    if query.get("story_fbid") and query["story_fbid"][0].strip():
        story_id = query["story_fbid"][0].strip()
        page_id = query.get("id", [""])[0].strip()
        return f"{page_id}_{story_id}" if page_id else story_id
    path_parts = [p for p in parsed.path.split("/") if p]
    for index, part in enumerate(path_parts):
        if part in {"posts", "videos", "photos", "reels", "permalink"} and index + 1 < len(path_parts):
            candidate = path_parts[index + 1].split("?")[0]
            if candidate.isdigit() or "_" in candidate:
                return candidate
    numeric_parts = [p for p in path_parts if p.isdigit()]
    if numeric_parts:
        return numeric_parts[-1]
    raise ValueError("تعذر استخراج post_id من الرابط. استخدم رابطًا مباشرًا لمنشور أو post_id.")


def get_access_token() -> str:
    """قراءة ACCESS_TOKEN من ملف البيئة أو متغيرات البيئة والتحقق من وجوده."""
    load_dotenv()
    token = os.getenv("ACCESS_TOKEN", "").strip()
    if not token:
        raise RuntimeError("لم يتم العثور على ACCESS_TOKEN. ضعه في البيئة أو ملف .env.")
    return token


def redact_url(url: str) -> str:
    """إزالة access_token من رابط API قبل تسجيله."""
    return re.sub(r"([?&]access_token=)[^&]+", r"\1REDACTED", url)


def graph_get(
    session: requests.Session,
    endpoint_or_url: str,
    token: str,
    params: Optional[Dict[str, Any]] = None,
    delay: float = DEFAULT_DELAY,
) -> Dict[str, Any]:
    """تنفيذ طلب GET إلى Graph API مع معالجة أخطاء OAuth وRate Limit."""
    time.sleep(max(0.0, delay))
    url = endpoint_or_url if endpoint_or_url.startswith("http") else f"{API_BASE}/{endpoint_or_url.lstrip('/')}"
    request_params = dict(params or {})
    request_params["access_token"] = token
    try:
        response = session.get(url, params=request_params, timeout=REQUEST_TIMEOUT)
        payload = response.json()
    except requests.exceptions.RequestException as exc:
        logger.exception("فشل الاتصال بـ Graph API: %s", exc)
        raise
    except ValueError as exc:
        logger.exception("استجابة Graph API ليست JSON: %s", exc)
        raise requests.exceptions.RequestException("Invalid JSON response") from exc

    error = payload.get("error") if isinstance(payload, dict) else None
    if response.status_code >= 400 or error:
        code = error.get("code") if isinstance(error, dict) else response.status_code
        message = error.get("message", "Unknown API error") if isinstance(error, dict) else str(payload)
        if code in (190, 102):
            logger.error("التوكن منتهٍ أو غير صالح (code=%s): %s", code, message)
            raise PermissionError("ACCESS_TOKEN منتهٍ أو غير صالح.")
        if code in (4, 17, 613, 80006) or response.status_code == 429:
            logger.warning("Rate Limit من Meta (code=%s): %s", code, message)
        else:
            logger.warning("رفض Graph API للطلب (code=%s): %s", code, message)
        raise requests.exceptions.HTTPError(f"Graph API error {code}: {message}")
    return payload


def paginate_comments(
    session: requests.Session, post_id: str, token: str, delay: float
) -> List[Dict[str, Any]]:
    """جلب جميع التعليقات عبر متابعة paging.next حتى انتهاء الصفحات."""
    comments: List[Dict[str, Any]] = []
    next_url: Optional[str] = f"{API_BASE}/{post_id}/comments"
    params: Optional[Dict[str, Any]] = {
        "fields": "from{id,name},message,created_time",
        "limit": 100,
    }
    page_count = 0
    while next_url:
        page_count += 1
        payload = graph_get(session, next_url, token, params=params, delay=delay)
        params = None
        data = payload.get("data", [])
        if not isinstance(data, list):
            raise KeyError("data")
        comments.extend(item for item in data if isinstance(item, dict))
        next_url = payload.get("paging", {}).get("next")
        if next_url:
            logger.info("تم جلب صفحة التعليقات رقم %d؛ الإجمالي: %d", page_count, len(comments))
    return comments


def try_get_user_data(
    session: requests.Session, user_id: str, token: str, delay: float
) -> Dict[str, Any]:
    """محاولة جلب بيانات الحساب المتاحة، مع طلبات منفصلة حتى لا يفشل كل شيء بسبب حقل واحد."""
    result: Dict[str, Any] = {"id": user_id}
    requests_to_try = [
        (user_id, {"fields": "id,name,picture{is_silhouette}"}, "profile"),
        (f"{user_id}/friends", {"summary": "true", "limit": 0}, "friends"),
        (f"{user_id}/posts", {"summary": "true", "limit": 0, "fields": "id"}, "posts"),
        (user_id, {"fields": "created_time"}, "created_time"),
    ]
    for endpoint, params, label in requests_to_try:
        try:
            data = graph_get(session, endpoint, token, params=params, delay=delay)
            if label == "profile":
                result.update(data)
            elif label == "friends":
                result["friends_count"] = data.get("summary", {}).get("total_count", 0)
            elif label == "posts":
                result["posts_count"] = data.get("summary", {}).get("total_count", 0)
            elif label == "created_time":
                result["created_time"] = data.get("created_time")
        except PermissionError:
            raise
        except (requests.exceptions.RequestException, KeyError, TypeError) as exc:
            logger.warning("تعذر جلب %s للمستخدم %s؛ سيتم استخدام fallback: %s", label, user_id, exc)
    return result


def parse_datetime(value: Any) -> Optional[datetime]:
    """تحويل timestamp بصيغة Graph API إلى datetime، أو None عند الفشل."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S+0000"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    return None


def normalize_text(text: str) -> str:
    """توحيد النص للمقارنة مع إزالة المسافات الزائدة وتحويل الأحرف إلى lowercase."""
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def text_score(message: str, repeated_count: int) -> Tuple[int, List[str]]:
    """حساب نقاط نص التعليق من 15 مع خصم التكرار والروابط ذات المؤشرات المشبوهة."""
    score = 15
    reasons: List[str] = []
    if repeated_count > 1:
        score -= min(8, 3 + (repeated_count - 2) * 2)
        reasons.append("نص مكرر")
    for url in SUSPICIOUS_URL_RE.findall(message or ""):
        lowered = url.lower().rstrip(".,!؟")
        if any(lowered.endswith(tld) or f"{tld}/" in lowered for tld in SUSPICIOUS_TLDS):
            score -= 7
            reasons.append("رابط ذو نطاق مشبوه")
            break
    if "http://" in (message or "").lower() or "https://" in (message or "").lower():
        if "رابط ذو نطاق مشبوه" not in reasons:
            score -= 3
            reasons.append("يحتوي رابطًا")
    return max(0, min(15, score)), reasons


def calculate_score(
    comment: Dict[str, Any], user_data: Dict[str, Any], repeated_count: int
) -> Tuple[int, List[str]]:
    """حساب مجموع النقاط وفق الأوزان المطلوبة مع اعتماد صفر عند غياب البيانات."""
    score = 0
    reasons: List[str] = []
    friends = user_data.get("friends_count")
    if isinstance(friends, (int, float)):
        if friends > 100:
            score += 30
        elif friends >= 50:
            score += 15
        else:
            score += 0
    else:
        reasons.append("friends_count غير متاح")

    picture = user_data.get("picture", {}).get("data", {}) if isinstance(user_data.get("picture"), dict) else {}
    if picture and picture.get("is_silhouette") is False:
        score += 20
    else:
        reasons.append("الصورة غير متاحة أو افتراضية")

    created = parse_datetime(user_data.get("created_time"))
    if created:
        age_days = (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).days
        score += 20 if age_days > 365 else 10 if age_days > 30 else 0
    else:
        reasons.append("عمر الحساب غير متاح")

    posts_count = user_data.get("posts_count")
    if isinstance(posts_count, (int, float)) and posts_count > 0:
        score += 15
    else:
        reasons.append("نشاط المنشورات غير متاح")

    message = comment.get("message", "")
    text_points, text_reasons = text_score(message, repeated_count)
    score += text_points
    reasons.extend(text_reasons)
    return max(0, min(100, score)), reasons


def classify(score: int) -> str:
    """إرجاع التصنيف العربي حسب حدود النقاط المطلوبة."""
    if score <= 40:
        return "وهمي"
    if score <= 60:
        return "مشبوه"
    return "حقيقي"


def analyze_comments(
    session: requests.Session, comments: Iterable[Dict[str, Any]], token: str, delay: float
) -> List[Dict[str, Any]]:
    """تحليل كل مستخدم فريد مع الحفاظ على تعليق ممثل له في التقرير."""
    comments_list = list(comments)
    text_counts = Counter(normalize_text(c.get("message", "")) for c in comments_list)
    by_user: Dict[str, Dict[str, Any]] = {}
    for comment in comments_list:
        author = comment.get("from") or {}
        user_id = str(author.get("id", "unknown"))
        if user_id not in by_user:
            by_user[user_id] = comment

    results: List[Dict[str, Any]] = []
    for user_id, comment in by_user.items():
        author = comment.get("from") or {}
        try:
            user_data = try_get_user_data(session, user_id, token, delay)
        except PermissionError:
            raise
        score, reasons = calculate_score(
            comment, user_data, text_counts[normalize_text(comment.get("message", ""))]
        )
        results.append({
            "user_id": user_id,
            "name": author.get("name", user_data.get("name", "غير معروف")),
            "comment": comment.get("message", ""),
            "comment_created_time": comment.get("created_time", ""),
            "friends_count": user_data.get("friends_count", 0),
            "has_real_profile_picture": bool(
                user_data.get("picture", {}).get("data", {}).get("is_silhouette") is False
            ),
            "account_age_available": bool(user_data.get("created_time")),
            "posts_count": user_data.get("posts_count", 0),
            "score": score,
            "classification": classify(score),
            "reasons": "; ".join(reasons) or "لا توجد مؤشرات سلبية واضحة",
        })
    return results


def print_ascii_report(results: List[Dict[str, Any]]) -> None:
    """طباعة جدول ASCII منسق للنتائج في الطرفية."""
    columns = [("user_id", "User ID", 18), ("name", "الاسم", 22), ("score", "Score", 7), ("classification", "التصنيف", 10)]
    line = "+" + "+".join("-" * (width + 2) for _, _, width in columns) + "+"
    print("\n" + line)
    print("|" + "|".join(f" {title[:width]:<{width}} " for _, title, width in columns) + "|")
    print(line)
    for row in results:
        print("|" + "|".join(f" {str(row.get(key, ''))[:width]:<{width}} " for key, _, width in columns) + "|")
    print(line)
    print(f"إجمالي الحسابات الفريدة: {len(results)}")


def save_reports(results: List[Dict[str, Any]], timestamp: str) -> Tuple[Path, Path]:
    """حفظ النتائج في CSV وJSON مع طابع زمني وإضافة UTF-8 BOM لملفات Excel."""
    csv_path = Path(f"report_{timestamp}.csv")
    json_path = Path(f"report_{timestamp}.json")
    dataframe = pd.DataFrame(results)
    dataframe.to_csv(csv_path, index=False, encoding="utf-8-sig", quoting=csv.QUOTE_MINIMAL)
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, ensure_ascii=False, indent=2)
    return csv_path, json_path


def save_chart(results: List[Dict[str, Any]]) -> Path:
    """إنشاء chart.png يوضح أعداد التصنيفات الثلاثة."""
    order = ["وهمي", "مشبوه", "حقيقي"]
    colors = ["#d62728", "#ff7f0e", "#2ca02c"]
    counts = Counter(row.get("classification") for row in results)
    plt.figure(figsize=(8, 5))
    bars = plt.bar(order, [counts.get(label, 0) for label in order], color=colors)
    plt.title("Facebook Commenter Classification")
    plt.xlabel("التصنيف")
    plt.ylabel("عدد الحسابات")
    plt.grid(axis="y", alpha=0.25)
    for bar in bars:
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(int(bar.get_height())), ha="center", va="bottom")
    plt.tight_layout()
    chart_path = Path("chart.png")
    plt.savefig(chart_path, dpi=160)
    plt.close()
    return chart_path


def parse_args() -> argparse.Namespace:
    """قراءة خيارات سطر الأوامر."""
    parser = argparse.ArgumentParser(description="تحليل تعليقات منشور فيسبوك")
    parser.add_argument("--url", help="رابط المنشور أو post_id")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="التأخير بين طلبات API بالثواني")
    return parser.parse_args()


def main() -> int:
    """تنفيذ دورة التحليل كاملة وإرجاع رمز خروج مناسب."""
    args = parse_args()
    timestamp = datetime.now().strftime("%Y_%m_%d")
    configure_logging(Path("error.log"))
    try:
        raw_url = args.url or input("أدخل رابط منشور فيسبوك: ").strip()
        post_id = extract_post_id(raw_url)
        token = get_access_token()
        logger.info("بدء تحليل المنشور %s باستخدام Graph API %s", post_id, API_VERSION)
        with requests.Session() as session:
            comments = paginate_comments(session, post_id, token, args.delay)
            logger.info("تم جلب %d تعليقًا", len(comments))
            if not comments:
                logger.warning("لم يتم العثور على تعليقات أو لا تسمح الصلاحيات بقراءتها.")
            results = analyze_comments(session, comments, token, args.delay)
        print_ascii_report(results)
        csv_path, json_path = save_reports(results, timestamp)
        chart_path = save_chart(results)
        print(f"\nتم إنشاء الملفات: {csv_path}, {json_path}, {chart_path}, error.log")
        return 0
    except (ValueError, RuntimeError, PermissionError) as exc:
        logger.error("فشل التنفيذ: %s", exc)
        print(f"خطأ: {exc}. راجع error.log.", file=sys.stderr)
        return 1
    except KeyError as exc:
        logger.exception("استجابة API تفتقد الحقل: %s", exc)
        print("خطأ: استجابة API ناقصة. راجع error.log.", file=sys.stderr)
        return 1
    except requests.exceptions.RequestException as exc:
        logger.exception("خطأ في طلب HTTP: %s", exc)
        print("خطأ في الاتصال أو صلاحيات API. راجع error.log.", file=sys.stderr)
        return 1
    except Exception as exc:
        logger.exception("خطأ غير متوقع: %s", exc)
        print("حدث خطأ غير متوقع. راجع error.log.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
