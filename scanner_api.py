import hashlib
import base64
import requests

# =========================================================
# ส่วนฟังก์ชันพื้นฐาน (Basic Utilities)
# =========================================================

def calculate_hash(file_bytes):
    """คำนวณค่า Hash (ลายนิ้วมือดิจิทัล) ของไฟล์ด้วยอัลกอริทึม SHA-256"""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()

def verify_hash(file_bytes, original_hash):
    """ตรวจสอบความถูกต้องของไฟล์ โดยนำ Hash ที่คำนวณใหม่ไปเทียบกับ Hash ต้นฉบับ"""
    file_hash = calculate_hash(file_bytes)
    original_hash = original_hash.strip().lower()
    return file_hash.lower() == original_hash, file_hash

# =========================================================
# Engine: VirusTotal API (Main Scanner)
# =========================================================

def get_analysis_stats(response):
    """
    อ่านผลลัพธ์ (JSON) จาก VirusTotal และรายงานตัวเลข พร้อมวิเคราะห์แพลตฟอร์มเป้าหมาย
    """
    if response.status_code == 200:
        data = response.json()
        attrs = data['data']['attributes']
        stats = attrs['last_analysis_stats']
        
        malicious = stats.get('malicious', 0)
        total = malicious + stats.get('undetected', 0) + stats.get('harmless', 0) + stats.get('suspicious', 0)
        
        # ==========================================
        # วิเคราะห์แพลตฟอร์มเป้าหมายจาก Tags ของมัลแวร์
        # ==========================================
        tags = attrs.get('tags', [])
        # ป้องกันกรณีไม่มี Tag ส่งมาให้ตั้งเป็น List ว่าง
        if not tags: 
            tags = []
            
        tags_lower = [str(t).lower() for t in tags]
        detected_platforms = [] # สร้างตะกร้าเปล่ามารอรับ

        # เช็กอิสระทุกเงื่อนไข เพื่อรองรับการโจมตีหลายระบบพร้อมกัน
        if any(ext in tags_lower for ext in ['android', 'apk', 'dex']):
            detected_platforms.append("📱 Android")
        if any(ext in tags_lower for ext in ['windows', 'peexe', 'msi', 'dll', 'exe']):
            detected_platforms.append("💻 Windows")
        if any(ext in tags_lower for ext in ['mac', 'macos', 'macho', 'dmg']):
            detected_platforms.append("🍏 macOS")
        if any(ext in tags_lower for ext in ['linux', 'elf']):
            detected_platforms.append("🐧 Linux")
        if any(ext in tags_lower for ext in ['ios', 'ipa']):
            detected_platforms.append("🍏 iOS")

        # สรุปผลลัพธ์
        if len(detected_platforms) > 0:
            platform_text = " และ ".join(detected_platforms)
        else:
            platform_text = "ไม่สามารถระบุได้แน่ชัด"
        # ==========================================

        if malicious == 0:
            return f"✅ ปลอดภัย ไม่พบภัยคุกคามจากผู้ให้บริการด้านความปลอดภัยทั้งหมด {total} รายการ\n🎯 แพลตฟอร์มเป้าหมาย: {platform_text}"
        else:
            return f"⚠️ ตรวจพบการแจ้งเตือนจากผู้ให้บริการด้านความปลอดภัย {malicious} เอนจิน จาก {total} เอนจิน\n🎯 แพลตฟอร์มเป้าหมาย: {platform_text}"
            
    elif response.status_code == 404:
        return "⚪ ไม่พบข้อมูลในระบบ อาจเป็นไฟล์ใหม่\n🎯 แพลตฟอร์มเป้าหมาย: ไม่สามารถระบุได้"
        
    else:
        return f"⚠️ ระบบขัดข้อง (Error: {response.status_code})\n🎯 แพลตฟอร์มเป้าหมาย: ไม่สามารถระบุได้"

def check_virustotal_file(file_hash, api_key):
    """ส่งค่า Hash ของไฟล์ไปตรวจสอบกับฐานข้อมูล VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return get_analysis_stats(response)

def check_virustotal_url(target_url, api_key):
    """ส่ง URL ไปตรวจสอบกับฐานข้อมูล VirusTotal"""
    # VT บังคับให้แปลง URL เป็น Base64 ก่อน
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return get_analysis_stats(response)

# ==========================================
# ส่วนสร้างลิงก์ Report ไปยัง VirusTotal
# ==========================================
def get_vt_file_report_url(file_hash):
    """สร้าง URL สำหรับกดไปดูผลสแกนไฟล์บนเว็บ VirusTotal"""
    return f"https://www.virustotal.com/gui/file/{file_hash}/detection"

def get_vt_url_report_url(url):
    """สร้าง URL สำหรับกดไปดูผลสแกนลิงก์บนเว็บ VirusTotal"""
    # กฎของ VT คือต้องแปลง URL เป็น Base64 และตัดเครื่องหมาย
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return f"https://www.virustotal.com/gui/url/{url_id}/detection"
