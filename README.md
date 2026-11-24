# RBX-Finder / ORC V2 — Universal Multi-Binary Analyzer & Offset Ledger

أداة هندسة عكسية وفحص شاملة موحدة تجمع كافة الأدوات السابقة (`elf_parser`, `header_generator`, `symbol_resolver`, `xref_engine`) في ملف واحد مستقل وقوي، مع دعم كامل للتحليل المتعدد للمكتبات، استخراج وفك ملفات الـ APK، فك تشفير جداول الدوال الدقيقة عبر `.eh_frame_hdr`، إدارة سجل المرشحين (Candidate Ledger)، محرك الاستعلام التفاعلي (Interactive Probe)، ومعالج أسئلة تفاعلي ذكي (Interactive Wizard).

---

## 🌟 الميزات الأساسية (Core Features)

1. **فحص المجلدات المتعددة وملفات الـ APK مباشرة (Multi-Binary & APK Support)**:
   - فحص مجلد يحتوي على عدة مكتبات (`libbacktrace-native.so`, `libdatastore_shared_counter.so`, `libimage_processing_util_jni.so`, `librenderscript-toolkit.so`, `libroblox.so`, `libsurface_util_jni.so`, `libtrampoline.so`, `libzstd-jni-1.5.7-6.so`).
   - استخراج مباشر لملفات الـ APK تلقائياً في الذاكرة دون الحاجة لأدوات خارجية وفحص مكتباتها المعمارية (`arm64-v8a`, `x86_64`).

2. **دقة حدود الدوال بنسبة 100% عبر `.eh_frame_hdr`**:
   - تفكيك وقراءة جداول إطارات الاستثناءات DWARF/LSB مباشرة من الكومبايلر لاستخراج البدايات الحقيقية لأكثر من 213,000 دالة بدقة متناهية.

3. **معالج إعداد تفاعلي ذكي (Interactive Questionnaire Wizard)**:
   - عند تشغيل الأداة مباشرة بدون وسائط أو باستخدام خيار `-i`، يطرح المعالج 8 أسئلة تفصيلية لتحديد الهدف، المكتبة، الفلاتر، أنماط البايتات، هياكل البيانات، ومسارات التصدير بدقة.

4. **دعم كامل ومتقدم لملف التواقيع `signatures.json`**:
   - دعم البحث بالأنماط البايتية المتقدمة ذات النصف بايت والـ wildcards (مثل `4?` أو `??`).
   - استخراج تلميحات هياكل البيانات (`struct_hints`) مثل إزاحات `Instance.children` و `TaskScheduler`.
   - فلترة مخصصة بالكلمات المفتاحية عبر `--sig-filter` (مثل: `loadstring,resume,datamodel`).

5. **نظام سجل المرشحين المتطور (Candidate Ledger Engine)**:
   - تصنيف دقيق للثقة (`high`, `medium`, `low`) والحالات (`needs_review`, `confirmed`, `rejected`, `live`).
   - ربط كل إزاحة وعنوان بسلسلة أدلة قطعية (`evidence`) مع توثيق البدائل المحتملة (`alternatives`).
   - أدوات CLI مدمجة لمراجعة وتأكيد وتدقيق السجلات (`summary`, `review`, `mark`, `check`).

6. **محرك التحقيق التفاعلي الفوري (Interactive Probe Engine)**:
   - استعلام سريع عن النصوص، الأنماط، مراجع الـ XRef، وقوائم الدوال مع تحديد الدالة الحاضنة بدقة.

7. **تصدير شامل لجميع بيئات التحليل (Multi-Format Export)**:
   - `Profile.hpp`: ترويسة C++ جاهزة للاستخدام في المشاريع والمعدلات.
   - `Profile_ledger.json`: سجل المرشحين الكامل للمراجعة والتدقيق.
   - `Profile_frida.js`: سكربت Frida جاهز للـ Hooking ورصد الاستدعاءات الحية.
   - `Profile_ghidra.py`: سكربت Python لبيئة Ghidra لإعادة تسمية الدوال وحقن الإشارات.
   - `Profile_ida.py`: سكربت IDC/IDAPython لبيئة IDA Pro.
   - `Profile_summary.md`: تقرير تحليلي وإحصائي كامل بتنسيق Markdown.
   - `Profile.json`: البيانات الخام الكاملة للـ AST والرموز.

---

## 🚀 طريقة الاستخدام السريعة (Quick Start)

### 1. الوضع التفاعلي (Interactive Wizard Mode)
لإطلاق المعالج التفاعلي ليقودك خطوة بخطوة:
```bash
python3 rbx_finder.py
# أو
python3 rbx_finder.py -i
```

### 2. فحص مجلد يحتوي على عدة مكتبات مع التصدير الكامل
```bash
python3 rbx_finder.py \
  /path/to/extracted_libs/ \
  --export-all /path/to/output/roblox_profile
```

### 3. فحص ملف APK مباشر مع تحديد مكتبة `libroblox.so` فقط
```bash
python3 rbx_finder.py \
  /path/to/roblox.apk \
  --lib libroblox.so \
  --export-all /path/to/output/roblox_profile
```

### 4. الفحص المخصص عبر التواقيع والفلترة (`signatures.json`)
```bash
python3 rbx_finder.py \
  /path/to/extracted_libs/ \
  --sig-path signatures.json \
  --sig-filter "loadstring,resume,datamodel,securityfiltercapabilities" \
  --export-all /path/to/output/filtered_profile
```

---

## 🔍 محرك التحقيق (Probe Engine)

يمكنك فحص أي مكتبة فورياً من سطر الأوامر دون الحاجة لفحص كامل:

* **البحث عن نص وتحديد دالته الحاضنة:**
  ```bash
  python3 rbx_finder.py probe libroblox.so string "Script Context"
  ```

* **البحث عن نمط بايتات (مع دعم Wildcards):**
  ```bash
  python3 rbx_finder.py probe libroblox.so pattern "FD 7B BE A9 ?? ?? ?? ??"
  ```

* **البحث عن مراجع XRef لعنوان معين:**
  ```bash
  python3 rbx_finder.py probe libroblox.so xref 0x3A2B1C
  ```

* **استعراض بدايات الدوال المستخرجة من `.eh_frame_hdr`:**
  ```bash
  python3 rbx_finder.py probe libroblox.so functions --limit 20
  ```

---

## 📋 إدارة سجل المرشحين (Candidate Ledger)

* **عرض ملخص إحصائي للسجل:**
  ```bash
  python3 rbx_finder.py ledger summary roblox_profile_ledger.json
  ```

* **مراجعة تفصيلية للمرشحين:**
  ```bash
  python3 rbx_finder.py ledger review roblox_profile_ledger.json
  ```

* **تأكيد أو رفض مرشح:**
  ```bash
  python3 rbx_finder.py ledger mark roblox_profile_ledger.json \
    --name loadstring \
    --status confirmed \
    --note "Verified via Ghidra decompilation" \
    --by c4
  ```

* **تدقيق سلامة السجل ومنع التعارضات:**
  ```bash
  python3 rbx_finder.py ledger check roblox_profile_ledger.json
  ```

---

## ⚙️ خيارات سطر الأوامر الكاملة (CLI Arguments)

| الخيار | الوصف |
|---|---|
| `target` | مسار ملف `.so`، أو مجلد مكتبات، أو ملف `.apk` |
| `--mode` | وضع السرعة (`fast` افتراضي، `normal`, `deep`, `paranoid`) |
| `--all-libs` | فحص كافة المكتبات في المجلد أو الأرشيف |
| `--lib` | استهداف مكتبة معينة بالاسم فقط (مثل `libroblox.so`) |
| `--sig-path` | تحديد مسار ملف `signatures.json` مخصص |
| `--sig-filter` | فلترة أسماء التواقيع بفواصل (مثل `loadstring,resume`) |
| `--no-patterns` | تعطيل فحص أنماط البايتات |
| `--no-struct-hints` | تعطيل استخراج تلميحات هياكل البيانات |
| `--min-len` | تحديد الحد الأدنى لطول النصوص الموسومة (الافتراضي: 4) |
| `--export-all` | تصدير كافة الصيغ (`.hpp`, `_frida.js`, `_ghidra.py`, `_ida.py`, `_ledger.json`, `_summary.md`, `.json`) لبادئة محددة |
| `--interactive`, `-i` | تشغيل المعالج التفاعلي خطوة بخطوة |
| `--quiet` | كتم الرسائل والشعار وتشغيل الفحص الصامت |
