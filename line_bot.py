from flask import Flask, request, abort
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import MessageEvent, TextMessage, TextSendMessage, ImageMessage, FileMessage
import scanner_api 
import zipfile
import io
import re
import os
from dotenv import load_dotenv

# สร้างแอปพลิเคชัน Flask เพื่อทำหน้าที่เป็น Web Server รับข้อมูลจาก LINE
app = Flask(__name__)

# ==========================================
# ตั้งค่าพื้นฐานและโหลดกุญแจความลับ
# ==========================================
load_dotenv()

# ==========================================
# 1. ตั้งค่ากุญแจความลับ (LINE กับ VT)
# ==========================================
LINE_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN")
LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET")
VT_API_KEY = os.getenv("VT_API_KEY")

line_bot_api = LineBotApi(LINE_ACCESS_TOKEN)
handler = WebhookHandler(LINE_CHANNEL_SECRET)

# ==========================================
# 2. ระบบวิเคราะห์และสร้างข้อความรายงาน
# ==========================================
def get_threat_advice(threat_text):
    """วิเคราะห์คำศัพท์จากผลสแกน เพื่อแยกประเภทภัยคุกคาม"""
    text = str(threat_text).lower()
    
    if "phishing" in text or "malicious" in text:
        return {"exp": "Phishing / Malicious: หน้าเว็บปลอมหรือไฟล์หลอกขโมยข้อมูล", "rec": "Action: ห้ามคลิกหรือเปิด ให้ลบทิ้งทันที"}
    elif "ransomware" in text or "wannacry" in text:
        return {"exp": "Ransomware: มัลแวร์เข้ารหัสข้อมูลเพื่อเรียกค่าไถ่", "rec": "Action: ห้ามรันเป้าหมายนี้เด็ดขาด! ลบทิ้งทันที"}
    elif "trojan" in text or "spyware" in text or "stealer" in text:
        return {"exp": "Trojan/Spyware: แอบขโมยข้อมูลหรือเปิดหลังบ้านให้แฮกเกอร์", "rec": "Action: ลบทิ้งทันที และทำการ Full Scan เครื่อง"}
    elif "hacktool" in text or "riskware" in text or "psexec" in text:
        return {"exp": "Riskware / HackTool: โปรแกรมเจาะระบบที่อาจเป็นอันตราย", "rec": "Action: หากไม่ได้ติดตั้งเองให้ลบทิ้ง"}
    elif "eicar" in text:
        return {"exp": "Test File: ไฟล์จำลองเพื่อใช้ทดสอบ ปลอดภัย 100%", "rec": "Action: ไม่ต้องดำเนินการใดๆ"}
    elif "password-protected" in text or "เข้ารหัสผ่าน" in text:
        return {"exp": "Encrypted Archive: ถูกล็อครหัสผ่าน ระบบสแกนไส้ในไม่ได้", "rec": "Action: ระมัดระวัง! ห้ามแตกไฟล์เด็ดขาด"}
    elif "❌" in text:
        return {"exp": "Unknown Malware: พบพฤติกรรมต้องสงสัย", "rec": "Action: หลีกเลี่ยงการเปิดใช้งาน"}
    
    return None

def generate_report_message(title, result, detail_name, detail_value, engine="VirusTotal"):
    """จัดรูปแบบข้อความตอบกลับสไตล์ LINE คล้าย Embed"""
    advice = get_threat_advice(result)
    
    reply = f"[{title}]\n\n"
    reply += f"{detail_name}: {detail_value}\n"
    reply += f"{'-'*20}\n"
    reply += f"ผลการสแกน:\n{result}\n"
    
    if advice:
        reply += f"{'-'*20}\n"
        reply += f"คำอธิบาย:\n{advice['exp']}\n\n"
        reply += f"คำแนะนำ:\n{advice['rec']}"
        
    return reply

# ==========================================
# 3. ประตูรับข้อมูล (Webhook Endpoint)
# ==========================================
@app.route("/webhook", methods=['POST'])
def callback():
    signature = request.headers['X-Line-Signature']
    body = request.get_data(as_text=True)
    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)
    return 'OK'

# ==========================================
# 4. ประมวลผลข้อความแชท (Text Detection)
# ==========================================
@handler.add(MessageEvent, message=TextMessage)
def handle_text_message(event):
    text = event.message.text
    
    # ดึง URL และ Hash จากข้อความ
    urls = re.findall(r'((?:https?://)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*))', text)
    hashes = re.findall(r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b', text)
    
    if urls:
        # ดึงแค่ลิงก์แรกที่เจอมาสแกน (เพราะ LINE ตอบได้ครั้งเดียว)
        u = urls[0]
        
        # ถ้าผู้ใช้พิมพ์มาไม่มี http ให้แอบเติมให้มันก่อนส่งไป API
        scan_url = u
        if not scan_url.startswith(('http://', 'https://')):
            scan_url = 'http://' + scan_url
            
        # ใช้ scan_url ที่เติม http แล้วส่งไปให้ API
        result = scanner_api.check_virustotal_url(scan_url, VT_API_KEY)
        
        # ตอนตอบกลับ คืนค่า u แบบออริจินัลให้ผู้ใช้เห็นว่าเราสแกนข้อความที่เขาพิมพ์มาจริงๆ
        reply_msg = generate_report_message("Link Scanning Results", result, "URL", u)
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_msg))
        
    elif hashes:
        # ดึงแค่ Hash แรกที่เจอ
        h = hashes[0]
        
        # เรียกใช้ check_virustotal_file
        result = scanner_api.check_virustotal_file(h, VT_API_KEY)
        
        reply_msg = generate_report_message("Hash Scanning Results", result, "Hash", h)
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_msg))

# ==========================================
# 5. ประมวลผลไฟล์และรูปภาพ (File/Image Detection)
# ==========================================
@handler.add(MessageEvent, message=(ImageMessage, FileMessage))
def handle_file_message(event):
    message_id = event.message.id
    if isinstance(event.message, FileMessage):
        file_name = event.message.file_name
    else:
        file_name = "Image_File.jpg"

    try:
        message_content = line_bot_api.get_message_content(message_id)
        # นำข้อมูลจาก LINE เป็นก้อนๆ มารวมกันไว้ที่ RAM ไม่แตะ Harddisk
        file_bytes = b"".join([chunk for chunk in message_content.iter_content()])

        if file_name.lower().endswith('.zip'):
            try:
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                    is_encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
                    if is_encrypted:
                        alert_msg = "❌ **Warning!** ไฟล์ถูกเข้ารหัสผ่าน (Password-Protected)"
                        reply_msg = generate_report_message("⚠️ Security Alert", alert_msg, "File name", file_name, engine="System")
                        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_msg))
                        return
            except zipfile.BadZipFile:
                pass

        # แล้วเอาข้อมูลที่เก็บไว้ใน RAM มาคำนวณ hash
        # เรียกใช้ calculate_hash
        file_hash = scanner_api.calculate_hash(file_bytes)
        
        # เรียกใช้ check_virustotal_file
        result = scanner_api.check_virustotal_file(file_hash, VT_API_KEY)
        
        reply_msg = generate_report_message("File Scan Report", result, "File name", file_name)
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_msg))

    except Exception as e:
        line_bot_api.reply_message(
            event.reply_token,
            TextSendMessage(text=f"⚠️ เกิดข้อผิดพลาดในการอ่านไฟล์: {str(e)}")
        )

# ==========================================
# 6. รันเซิร์ฟเวอร์
# ==========================================
if __name__ == "__main__":
    app.run(port=8080, debug=True)