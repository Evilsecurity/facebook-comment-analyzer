# Facebook Comment Analyzer

سكربت بايثون لتحليل تعليقات منشور Facebook عبر Graph API v18.0، مع تصنيف heuristic للحسابات إلى: وهمي، مشبوه، أو حقيقي.

## التثبيت

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## إعداد Access Token

أنشئ ملف `.env` في مجلد المشروع:

```env
ACCESS_TOKEN=YOUR_FACEBOOK_ACCESS_TOKEN
```

أو استخدم متغير البيئة مباشرة:

```bash
export ACCESS_TOKEN="YOUR_FACEBOOK_ACCESS_TOKEN"
```

## التشغيل

```bash
python fb_analyzer.py --url "https://www.facebook.com/username/posts/123456789"
```

يمكن تعديل التأخير بين الطلبات:

```bash
python fb_analyzer.py --url "POST_URL" --delay 0.8
```

ينتج السكربت ملفات CSV وJSON مؤرخة، ورسمًا باسم `chart.png`، وسجل أخطاء باسم `error.log`.

## ملاحظات الخصوصية والدقة

هذا التصنيف heuristic وليس إثباتًا لهوية الحساب. تعتمد البيانات المتاحة على نوع التوكن وصلاحيات التطبيق وإعدادات الخصوصية. قد لا توفر Meta عدد الأصدقاء الحقيقي أو تاريخ إنشاء حسابات المعلقين الآخرين؛ عندها يستخدم السكربت قيمًا محايدة ويسجل التحذير ويعتمد على البيانات المتاحة وتحليل النص.

لا تضع Access Token داخل الكود أو المستودع. ملف `.env` مضاف إلى `.gitignore`.
