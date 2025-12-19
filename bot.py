import logging
import os 
import threading
import time
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler
import ipaddress
import socket
import subprocess
import concurrent.futures
import signal
import sys
import asyncio
import json

# ✅ Logging Configuration
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ✅ SECURITY: Environment Variables (GitHub Actions Secrets)
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID", "")
STORAGE_CHAT_ID = os.getenv("STORAGE_CHAT_ID", "")

# ✅ Validate Environment Variables
if not BOT_TOKEN:
    logger.error("❌ TELEGRAM_BOT_TOKEN not set!")
    sys.exit(1)

if not ADMIN_CHAT_ID:
    logger.error("❌ ADMIN_CHAT_ID not set!")
    sys.exit(1)

if not STORAGE_CHAT_ID:
    STORAGE_CHAT_ID = ADMIN_CHAT_ID
    logger.warning("⚠️ STORAGE_CHAT_ID not set, using ADMIN_CHAT_ID")

logger.info(f"✅ Bot Token: {BOT_TOKEN[:15]}...")
logger.info(f"✅ Admin Chat: {ADMIN_CHAT_ID}")
logger.info(f"✅ Storage Chat: {STORAGE_CHAT_ID}")

# ✅ Port Scan Configuration
QUICK_SCAN_PORTS = [80, 443, 8080, 8443, 3000, 5000, 7001, 8000, 8081, 8181, 9000, 9090]
DEFAULT_HTTPS_PORTS = [443, 8443, 9443, 2443, 3443, 4443, 5443, 6443, 7443]

scan_lock = threading.RLock()

# ✅ File Storage System
class FileStorage:
    def __init__(self):
        self.stored_files = {}
        self.storage_file = "file_storage.json"
        self.load_storage()
    
    def load_storage(self):
        """Load file storage from JSON"""
        try:
            if os.path.exists(self.storage_file):
                with open(self.storage_file, "r") as f:
                    self.stored_files = json.load(f)
                logger.info(f"📂 Loaded {len(self.stored_files)} stored file records")
            else:
                logger.info("📂 No existing storage file, starting fresh")
                self.stored_files = {}
        except Exception as e:
            logger.error(f"❌ Error loading storage: {e}")
            self.stored_files = {}
    
    def save_storage(self):
        """Save file storage to JSON"""
        try:
            with open(self.storage_file, "w") as f:
                json.dump(self.stored_files, f, indent=2)
            logger.info("💾 File storage saved successfully")
        except Exception as e:
            logger.error(f"❌ Error saving storage: {e}")
    
    def add_files(self, scan_id, detailed_file_id, ip_list_file_id, cidr, active_ips, timestamp):
        """Add file IDs to storage"""
        self.stored_files[scan_id] = {
            'detailed_file_id': detailed_file_id,
            'ip_list_file_id': ip_list_file_id,
            'cidr': cidr,
            'active_ips': active_ips,
            'timestamp': timestamp,
            'date': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        }
        self.save_storage()
        logger.info(f"✅ Added scan {scan_id} to storage")
    
    def get_all_scans(self):
        """Get list of all stored scans (sorted by newest first)"""
        return sorted(self.stored_files.items(), key=lambda x: x[1]['timestamp'], reverse=True)
    
    def get_scan(self, scan_id):
        """Get specific scan by ID"""
        return self.stored_files.get(scan_id)

file_storage = FileStorage()

# ✅ Scan Status Tracker
class ScanStatus:
    def __init__(self):
        self.is_scanning = False
        self.should_stop = False
        self.total_ips = 0
        self.scanned_ips = 0
        self.active_ips = 0
        self.current_ip = ''
        self.start_time = None
        self.cidr = ''
        self.scan_results = []
        self.chat_id = None
        self.last_update_time = None
        self.scan_id = None
    
    def reset_for_new_scan(self, cidr, total_ips, chat_id):
        with scan_lock:
            self.is_scanning = True
            self.should_stop = False
            self.total_ips = total_ips
            self.scanned_ips = 0
            self.active_ips = 0
            self.current_ip = 'Initializing...'
            self.start_time = time.time()
            self.cidr = cidr
            self.scan_results = []
            self.chat_id = chat_id
            self.last_update_time = time.time()
            self.scan_id = f"{int(time.time())}_{cidr.replace('/', '_')}"
            logger.info(f"✅ New scan initialized: {self.scan_id}")
    
    def increment_scanned(self):
        with scan_lock:
            self.scanned_ips += 1
    
    def increment_active(self):
        with scan_lock:
            self.active_ips += 1
    
    def set_current_ip(self, ip):
        with scan_lock:
            self.current_ip = ip
    
    def add_result(self, result):
        with scan_lock:
            self.scan_results.append(result)
    
    def get_status_dict(self):
        with scan_lock:
            return {
                'is_scanning': self.is_scanning,
                'total_ips': self.total_ips,
                'scanned_ips': self.scanned_ips,
                'active_ips': self.active_ips,
                'current_ip': self.current_ip,
                'start_time': self.start_time,
                'cidr': self.cidr,
                'has_results': len(self.scan_results) > 0,
                'results_count': len(self.scan_results),
                'chat_id': self.chat_id,
                'last_update_time': self.last_update_time,
                'scan_id': self.scan_id
            }
    
    def update_last_update_time(self):
        with scan_lock:
            self.last_update_time = time.time()
    
    def stop_scan(self):
        with scan_lock:
            self.should_stop = True
            logger.info("🛑 Stop signal received")
    
    def is_stopped(self):
        with scan_lock:
            return self.should_stop
    
    def mark_complete(self):
        with scan_lock:
            self.is_scanning = False
            logger.info("✅ Scan marked as complete")

scan_status = ScanStatus()
app_instance = None

# ✅ Port Scanning Functions
def check_port_open(ip_str, port):
    """Check if a port is open on given IP"""
    if scan_status.is_stopped():
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip_str, port))
        sock.close()
        return result == 0
    except:
        return False

def get_http_status(ip_str, port):
    """Get HTTP status code from web server"""
    if scan_status.is_stopped():
        return "STOPPED"
    try:
        protocol = "https" if port in DEFAULT_HTTPS_PORTS else "http"
        url = f"{protocol}://{ip_str}:{port}"
        cmd = ["curl", "-i", "-k", "--connect-timeout", "2", "-m", "3", url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
        if "HTTP/" in result.stdout:
            status_line = result.stdout.splitlines()[0]
            parts = status_line.split()
            if len(parts) >= 2:
                return parts[1]
        return "N/A"
    except:
        return "N/A"

def scan_ip(ip_str, ports):
    """Scan a single IP for open ports"""
    if scan_status.is_stopped():
        scan_status.increment_scanned()
        return None
    
    try:
        scan_status.set_current_ip(ip_str)
        
        # Try to resolve hostname
        try:
            hostname = socket.gethostbyaddr(ip_str)[0][:18]
        except:
            hostname = "N/A"
        
        open_ports = []
        port_details = []
        
        # Scan each port
        for port in ports:
            if scan_status.is_stopped():
                break
            
            if check_port_open(ip_str, port):
                open_ports.append(port)
                http_status = get_http_status(ip_str, port)
                port_details.append({'port': port, 'http_status': http_status})
        
        scan_status.increment_scanned()
        
        if open_ports:
            scan_status.increment_active()
            logger.info(f"✅ Active IP found: {ip_str} - {len(open_ports)} open ports")
            return {'ip': ip_str, 'hostname': hostname, 'ports': port_details}
        
        return None
        
    except Exception as e:
        logger.debug(f"Error scanning {ip_str}: {e}")
        scan_status.increment_scanned()
        return None

# ✅ File Saving Functions
def save_scan_results():
    """Save scan results to text files"""
    try:
        status_dict = scan_status.get_status_dict()
        
        with scan_lock:
            results = scan_status.scan_results.copy()
        
        if not results:
            logger.warning("⚠️ No results to save")
            return False
        
        # File 1: Detailed report with all information
        detailed_file = "ip.txt"
        with open(detailed_file, "w", encoding='utf-8') as f:
            f.write(f"╔═══════════════════════════════════════════════════════════╗\n")
            f.write(f"║        CIDRProbe Scan Results - Detailed Report         ║\n")
            f.write(f"╚═══════════════════════════════════════════════════════════╝\n\n")
            f.write(f"🆔 Scan ID: {status_dict['scan_id']}\n")
            f.write(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"🎯 CIDR: {status_dict['cidr']}\n")
            f.write(f"✅ Total Active Hosts: {len(results)}\n")
            f.write(f"📊 Total Scanned: {status_dict['scanned_ips']}\n\n")
            f.write("═" * 70 + "\n\n")
            
            for idx, result in enumerate(results, 1):
                f.write(f"[{idx}] IP Address: {result['ip']}\n")
                if result['hostname'] != "N/A":
                    f.write(f"    Hostname: {result['hostname']}\n")
                
                port_list = []
                for port_info in result['ports']:
                    port_list.append(f"{port_info['port']} (HTTP:{port_info['http_status']})")
                
                f.write(f"    Open Ports: {', '.join(port_list)}\n")
                f.write("-" * 70 + "\n\n")
        
        logger.info(f"✅ Detailed report saved: {detailed_file}")
        
        # File 2: Simple IP list (one IP per line)
        ip_list_file = "live_ips.txt"
        with open(ip_list_file, "w", encoding='utf-8') as f:
            f.write(f"# Live IPs with Open Ports\n")
            f.write(f"# Scan ID: {status_dict['scan_id']}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# CIDR: {status_dict['cidr']}\n")
            f.write(f"# Total Active IPs: {len(results)}\n")
            f.write(f"# ═══════════════════════════════════════════════\n\n")
            
            for result in results:
                f.write(f"{result['ip']}\n")
        
        logger.info(f"✅ IP list saved: {ip_list_file}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error saving results: {e}")
        import traceback
        traceback.print_exc()
        return False

# ✅ File Upload Functions
async def upload_files_to_storage(chat_id, cidr, active_ips, scan_id):
    """Upload scan results to Telegram storage with retry logic"""
    try:
        logger.info(f"📤 Starting file upload for scan {scan_id}")
        
        detailed_file_id = None
        ip_list_file_id = None
        
        # Verify files exist
        if not os.path.exists("ip.txt") or not os.path.exists("live_ips.txt"):
            logger.error("❌ Required files not found for upload")
            return False
        
        max_retries = 3
        retry_delay = 5
        
        # Upload detailed report
        for attempt in range(max_retries):
            try:
                logger.info(f"📤 Uploading detailed report (attempt {attempt + 1}/{max_retries})")
                
                with open("ip.txt", "rb") as f:
                    msg = await asyncio.wait_for(
                        app_instance.bot.send_document(
                            chat_id=STORAGE_CHAT_ID,
                            document=f,
                            filename=f"scan_{scan_id}_detailed.txt",
                            caption=f"🗄️ *Storage: Detailed Report*\n\n📊 Scan: `{cidr}`\n✅ Active IPs: {active_ips}\n🆔 ID: `{scan_id}`",
                            parse_mode='Markdown',
                            read_timeout=60,
                            write_timeout=60,
                            connect_timeout=60
                        ),
                        timeout=120
                    )
                    detailed_file_id = msg.document.file_id
                    logger.info(f"✅ Detailed report uploaded: {detailed_file_id}")
                    break
                    
            except asyncio.TimeoutError:
                logger.warning(f"⚠️ Upload timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                else:
                    logger.error("❌ Detailed report upload failed after all retries")
                    return False
                    
            except Exception as e:
                logger.error(f"❌ Upload error: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                else:
                    return False
        
        # Upload IP list
        for attempt in range(max_retries):
            try:
                logger.info(f"📤 Uploading IP list (attempt {attempt + 1}/{max_retries})")
                
                with open("live_ips.txt", "rb") as f:
                    msg = await asyncio.wait_for(
                        app_instance.bot.send_document(
                            chat_id=STORAGE_CHAT_ID,
                            document=f,
                            filename=f"scan_{scan_id}_ips.txt",
                            caption=f"🗄️ *Storage: IP List*\n\n📊 Scan: `{cidr}`\n✅ Active IPs: {active_ips}\n🆔 ID: `{scan_id}`",
                            parse_mode='Markdown',
                            read_timeout=60,
                            write_timeout=60,
                            connect_timeout=60
                        ),
                        timeout=120
                    )
                    ip_list_file_id = msg.document.file_id
                    logger.info(f"✅ IP list uploaded: {ip_list_file_id}")
                    break
                    
            except asyncio.TimeoutError:
                logger.warning(f"⚠️ Upload timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                else:
                    logger.error("❌ IP list upload failed after all retries")
                    return False
                    
            except Exception as e:
                logger.error(f"❌ Upload error: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                else:
                    return False
        
        # Store file IDs if both uploads succeeded
        if detailed_file_id and ip_list_file_id:
            file_storage.add_files(
                scan_id=scan_id,
                detailed_file_id=detailed_file_id,
                ip_list_file_id=ip_list_file_id,
                cidr=cidr,
                active_ips=active_ips,
                timestamp=time.time()
            )
            logger.info("✅ File IDs stored in database")
            return True
        
        logger.error("❌ Missing file IDs after upload")
        return False
        
    except Exception as e:
        logger.error(f"❌ Storage upload critical error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def send_completion_results(chat_id, cidr, active_ips, total_scanned, elapsed_time, scan_id):
    """Send scan completion results to user"""
    try:
        logger.info(f"📤 Sending completion results to chat {chat_id}")
        
        # Send completion notification
        completion_text = f"""
🎉 *SCAN COMPLETED!*

━━━━━━━━━━━━━━━━━━━━━
🎯 *Target CIDR:* `{cidr}`
📊 *Total Scanned:* {total_scanned} IPs
✅ *Active IPs Found:* {active_ips}
⏱️ *Time Taken:* {int(elapsed_time)}s ({elapsed_time/60:.1f} min)
🆔 *Scan ID:* `{scan_id}`
━━━━━━━━━━━━━━━━━━━━━

📁 Preparing result files...
        """
        
        await app_instance.bot.send_message(
            chat_id=chat_id,
            text=completion_text,
            parse_mode='Markdown'
        )
        
        # Send files to user
        files_sent = 0
        
        if os.path.exists("ip.txt"):
            try:
                with open("ip.txt", "rb") as f:
                    await app_instance.bot.send_document(
                        chat_id=chat_id,
                        document=f,
                        filename=f"detailed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        caption=f"📊 *Detailed Report*\n✅ {active_ips} Active IPs with port details",
                        parse_mode='Markdown',
                        read_timeout=60,
                        write_timeout=60
                    )
                    files_sent += 1
                    logger.info("✅ Detailed report sent to user")
            except Exception as e:
                logger.error(f"❌ Failed to send detailed report: {e}")
        
        if os.path.exists("live_ips.txt"):
            try:
                with open("live_ips.txt", "rb") as f:
                    await app_instance.bot.send_document(
                        chat_id=chat_id,
                        document=f,
                        filename=f"live_ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        caption=f"📋 *IP List*\n✅ {active_ips} Active IPs (plain list)",
                        parse_mode='Markdown',
                        read_timeout=60,
                        write_timeout=60
                    )
                    files_sent += 1
                    logger.info("✅ IP list sent to user")
            except Exception as e:
                logger.error(f"❌ Failed to send IP list: {e}")
        
        # Upload to permanent storage
        logger.info("📤 Starting upload to permanent storage...")
        storage_success = await upload_files_to_storage(chat_id, cidr, active_ips, scan_id)
        
        # Send final status message
        if storage_success:
            await app_instance.bot.send_message(
                chat_id=chat_id,
                text=f"""✅ *Results Delivered Successfully!*

🗄️ Files uploaded to bot storage
📁 {files_sent} file(s) sent to you
🆔 Scan ID: `{scan_id}`

📂 View all scans: /history
📥 Download again: /download
🔄 New scan: /scan""",
                parse_mode='Markdown'
            )
        else:
            await app_instance.bot.send_message(
                chat_id=chat_id,
                text=f"""⚠️ *Partial Success*

✅ {files_sent} file(s) sent to you
❌ Storage upload encountered errors

💡 Files are still available via /download
🔧 Check logs for details""",
                parse_mode='Markdown'
            )
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error sending completion results: {e}")
        import traceback
        traceback.print_exc()
        
        # Try to send error notification
        try:
            await app_instance.bot.send_message(
                chat_id=chat_id,
                text=f"❌ *Error sending results*\n\nPlease check logs or use /download",
                parse_mode='Markdown'
            )
        except:
            pass
        
        return False

# ✅ Main Scan Function
def perform_scan(cidr, chat_id):
    """Main scanning logic"""
    try:
        logger.info(f"🚀 Starting scan for CIDR: {cidr}")
        
        # Parse CIDR notation
        try:
            ip_network = ipaddress.ip_network(cidr)
            total_hosts = ip_network.num_addresses - 2  # Exclude network and broadcast
            logger.info(f"📊 Network parsed: {total_hosts} hosts to scan")
        except Exception as e:
            logger.error(f"❌ Invalid CIDR notation: {e}")
            return
        
        # Initialize scan status
        scan_status.reset_for_new_scan(cidr, total_hosts, chat_id)
        
        time.sleep(0.5)
        
        # Verify scan started
        status_check = scan_status.get_status_dict()
        if not status_check['is_scanning']:
            logger.error("❌ Failed to initialize scan status!")
            return
        
        logger.info(f"📡 Starting IP scan with {len(QUICK_SCAN_PORTS)} ports per host")
        
        # Get list of IPs to scan
        ip_list = list(ip_network.hosts())
        logger.info(f"📋 Generated {len(ip_list)} IPs to scan")
        
        # Scan IPs concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            
            # Submit all scan jobs
            for ip in ip_list:
                if scan_status.is_stopped():
                    break
                future = executor.submit(scan_ip, str(ip), QUICK_SCAN_PORTS)
                futures.append(future)
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                if scan_status.is_stopped():
                    executor.shutdown(wait=False)
                    logger.info("🛑 Scan stopped by user")
                    break
                
                try:
                    result = future.result(timeout=15)
                    if result:
                        scan_status.add_result(result)
                except Exception as e:
                    logger.debug(f"Error processing result: {e}")
        
        # Get final status
        status_dict = scan_status.get_status_dict()
        elapsed = time.time() - status_dict['start_time']
        
        logger.info(f"✅ Scan complete!")
        logger.info(f"   Scanned: {status_dict['scanned_ips']}/{status_dict['total_ips']}")
        logger.info(f"   Active: {status_dict['active_ips']}")
        logger.info(f"   Time: {elapsed:.1f}s")
        
        # Process results if not stopped
        if not scan_status.is_stopped() and status_dict['active_ips'] > 0:
            logger.info("💾 Saving scan results...")
            if not save_scan_results():
                logger.error("❌ Failed to save scan results")
                scan_status.mark_complete()
                return
            
            # Send results to user
            if chat_id and app_instance:
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_closed():
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    
                    future = asyncio.run_coroutine_threadsafe(
                        send_completion_results(
                            chat_id, 
                            cidr, 
                            status_dict['active_ips'], 
                            status_dict['scanned_ips'], 
                            elapsed,
                            status_dict['scan_id']
                        ),
                        loop
                    )
                    
                    result = future.result(timeout=300)  # 5 minutes timeout
                    logger.info(f"✅ Results delivery completed: {result}")
                    
                except Exception as e:
                    logger.error(f"❌ Error in results delivery: {e}")
                    import traceback
                    traceback.print_exc()
        elif status_dict['active_ips'] == 0:
            logger.info("ℹ️ No active IPs found")
            if chat_id and app_instance:
                try:
                    loop = asyncio.get_event_loop()
                    asyncio.run_coroutine_threadsafe(
                        app_instance.bot.send_message(
                            chat_id=chat_id,
                            text=f"ℹ️ *Scan Complete*\n\n🎯 CIDR: `{cidr}`\n❌ No active IPs found\n📊 Scanned: {status_dict['scanned_ips']} IPs",
                            parse_mode='Markdown'
                        ),
                        loop
                    )
                except:
                    pass
        
        scan_status.mark_complete()
        logger.info("✅ Scan fully completed")
        
    except Exception as e:
        logger.error(f"❌ CRITICAL SCAN ERROR: {e}")
        import traceback
        traceback.print_exc()
        scan_status.mark_complete()

# ✅ Bot Command Handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    keyboard = [
        [InlineKeyboardButton("📊 Status", callback_data='status')],
        [InlineKeyboardButton("🚀 Start Scan", callback_data='scan_prompt')],
        [InlineKeyboardButton("📂 History", callback_data='history')],
        [InlineKeyboardButton("🛑 Stop", callback_data='stop')],
        [InlineKeyboardButton("📥 Download", callback_data='download')],
        [InlineKeyboardButton("❓ Help", callback_data='help')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = """
🤖 *CIDRProbe Bot v5.1*
━━━━━━━━━━━━━━━━━━━━━

Automated IP & Port Scanner with Cloud Storage

*✨ Features:*
• 📊 Real-time scan progress
• 🎯 Auto-result delivery
• 🗄️ Permanent file storage
• 📂 Scan history tracking
• 📁 Two output formats
• 🔔 Periodic updates (10min)
• 🛑 Stop scan anytime
• ✅ Retry logic for reliability

*📝 Commands:*
/scan <CIDR> - Start new scan
/status - Check progress
/history - View all scans
/download - Get latest files
/stop - Stop current scan
/help - Show help

*💡 Example:*
`/scan 192.168.1.0/24`
`/scan 10.0.0.0/16`

━━━━━━━━━━━━━━━━━━━━━
Created for Network Reconnaissance
    """
    
    await update.message.reply_text(
        welcome_text, 
        reply_markup=reply_markup, 
        parse_mode='Markdown'
    )

def get_status_text():
    """Generate status message text"""
    status_dict = scan_status.get_status_dict()
    
    if status_dict['is_scanning']:
        elapsed = time.time() - status_dict['start_time']
        progress = (status_dict['scanned_ips'] / status_dict['total_ips'] * 100) if status_dict['total_ips'] > 0 else 0
        
        # Progress bar
        bar_length = 20
        filled = int(bar_length * progress / 100)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        # Calculate ETA
        eta = (elapsed / status_dict['scanned_ips'] * (status_dict['total_ips'] - status_dict['scanned_ips'])) if status_dict['scanned_ips'] > 0 else 0
        speed = status_dict['scanned_ips']/elapsed if elapsed > 0 else 0
        
        return f"""
🔄 *SCAN IN PROGRESS*

{bar} {progress:.1f}%

🎯 *Target:* `{status_dict['cidr']}`
📈 *Progress:* {status_dict['scanned_ips']}/{status_dict['total_ips']} IPs
✅ *Active Found:* {status_dict['active_ips']}
🔍 *Current IP:* `{status_dict['current_ip']}`
⏱️ *Elapsed:* {int(elapsed)}s
⚡ *Speed:* {speed:.1f} IP/s
⏰ *ETA:* ~{int(eta)}s

_Results will be uploaded automatically on completion_
        """
    elif status_dict['has_results']:
        return f"""
✅ *SCAN COMPLETED*

━━━━━━━━━━━━━━━━━━━━━
🎯 *CIDR:* `{status_dict['cidr']}`
✅ *Active IPs:* {status_dict['active_ips']}
📊 *Total Scanned:* {status_dict['scanned_ips']}
🗄️ *Status:* Files stored in bot
🆔 *Scan ID:* `{status_dict['scan_id']}`
━━━━━━━━━━━━━━━━━━━━━

📂 View history: /history
📥 Download files: /download
🔄 New scan: /scan <CIDR>
        """
    else:
        return """
💤 *NO ACTIVE SCAN*

━━━━━━━━━━━━━━━━━━━━━
Ready to start scanning!

*Quick Start:*
`/scan 192.168.1.0/24`
`/scan 10.0.0.0/16`

*Features:*
🗄️ Auto file storage
📂 Scan history
📥 Re-download anytime
━━━━━━━━━━━━━━━━━━━━━
        """

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /status command"""
    status_text = get_status_text()
    status_dict = scan_status.get_status_dict()
    
    keyboard = []
    if status_dict['is_scanning']:
        keyboard.append([InlineKeyboardButton("🔄 Refresh", callback_data='status')])
        keyboard.append([InlineKeyboardButton("🛑 Stop", callback_data='stop')])
    else:
        keyboard.append([InlineKeyboardButton("📂 History", callback_data='history')])
        keyboard.append([InlineKeyboardButton("🚀 New Scan", callback_data='scan_prompt')])
    
    reply_markup = InlineKeyboardMarkup(keyboard) if keyboard else None
    await update.message.reply_text(status_text, reply_markup=reply_markup, parse_mode='Markdown')

async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /history command - show scan history"""
    scans = file_storage.get_all_scans()
    
    if not scans:
        await update.message.reply_text(
            "📂 *No Scan History*\n\n"
            "No previous scans found.\n"
            "Run /scan to create your first scan!",
            parse_mode='Markdown'
        )
        return
    
    history_text = f"""
📂 *SCAN HISTORY*
━━━━━━━━━━━━━━━━━━━━━

🗄️ Total scans: {len(scans)}

"""
    
    # Show last 10 scans
    for i, (scan_id, data) in enumerate(scans[:10], 1):
        history_text += f"{i}. `{data['cidr']}`\n"
        history_text += f"   ✅ {data['active_ips']} IPs | 📅 {data['date']}\n"
        history_text += f"   🆔 `{scan_id}`\n\n"
    
    if len(scans) > 10:
        history_text += f"_...and {len(scans) - 10} more scans_\n\n"
    
    history_text += "━━━━━━━━━━━━━━━━━━━━━"
    
    # Create download buttons for recent scans
    keyboard = []
    for scan_id, data in scans[:5]:
        keyboard.append([InlineKeyboardButton(
            f"📥 {data['cidr']} ({data['active_ips']} IPs)",
            callback_data=f"getfile_{scan_id}"
        )])
    
    keyboard.append([InlineKeyboardButton("🔄 Refresh History", callback_data='history')])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(history_text, reply_markup=reply_markup, parse_mode='Markdown')

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /scan command"""
    # Check if already scanning
    if scan_status.get_status_dict()['is_scanning']:
        await update.message.reply_text(
            "⚠️ *Scan Already Running!*\n\n"
            "Please wait for current scan to complete or use /stop first.",
            parse_mode='Markdown'
        )
        return
    
    # Check if CIDR provided
    if not context.args:
        await update.message.reply_text(
            "❌ *Missing CIDR notation!*\n\n"
            "*Usage:* /scan <CIDR>\n\n"
            "*Examples:*\n"
            "`/scan 192.168.1.0/24` - Scan 254 IPs\n"
            "`/scan 10.0.0.0/16` - Scan 65,534 IPs\n"
            "`/scan 172.16.0.0/12` - Scan 1,048,574 IPs",
            parse_mode='Markdown'
        )
        return
    
    cidr = context.args[0]
    
    # Validate CIDR
    try:
        network = ipaddress.ip_network(cidr)
        host_count = network.num_addresses - 2
        
        # Warn for large networks
        if host_count > 10000:
            await update.message.reply_text(
                f"⚠️ *Large Network Detected!*\n\n"
                f"🎯 CIDR: `{cidr}`\n"
                f"📊 IPs to scan: {host_count:,}\n"
                f"⏱️ Estimated time: ~{host_count // 100} minutes\n\n"
                f"This will take considerable time. Continue?",
                parse_mode='Markdown'
            )
    except Exception as e:
        await update.message.reply_text(
            f"❌ *Invalid CIDR notation!*\n\n"
            f"Error: `{str(e)}`\n\n"
            f"Please use valid CIDR format like:\n"
            f"`192.168.1.0/24`",
            parse_mode='Markdown'
        )
        return
    
    chat_id = update.effective_chat.id
    
    # Send starting message
    await update.message.reply_text(
        f"🚀 *Starting Scan...*\n\n"
        f"🎯 Target: `{cidr}`\n"
        f"📊 Total IPs: {host_count:,}\n"
        f"🔍 Ports per IP: {len(QUICK_SCAN_PORTS)}\n"
        f"🗄️ Auto-upload: Enabled\n\n"
        f"_Initializing scan engine..._",
        parse_mode='Markdown'
    )
    
    # Start scan in background thread
    scan_thread = threading.Thread(
        target=perform_scan,
        args=(cidr, chat_id),
        daemon=True,
        name=f"ScanThread-{cidr}"
    )
    scan_thread.start()
    
    time.sleep(2)
    
    # Send confirmation with action buttons
    keyboard = [
        [InlineKeyboardButton("📊 Check Status", callback_data='status')],
        [InlineKeyboardButton("🛑 Stop Scan", callback_data='stop')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "✅ *Scan Started Successfully!*\n\n"
        "📊 Monitor progress: /status\n"
        "🗄️ Files will be auto-stored\n"
        "📂 View history: /history\n\n"
        "_Scanning in progress..._",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )

async def stop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /stop command"""
    if not scan_status.get_status_dict()['is_scanning']:
        await update.message.reply_text(
            "ℹ️ *No Active Scan*\n\n"
            "There is no scan running at the moment.",
            parse_mode='Markdown'
        )
        return
    
    # Send stopping signal
    scan_status.stop_scan()
    await update.message.reply_text(
        "🛑 *Stopping Scan...*\n\n"
        "Please wait while the scan is terminated gracefully.",
        parse_mode='Markdown'
    )
    
    time.sleep(2)
    
    # Show final status
    status_dict = scan_status.get_status_dict()
    await update.message.reply_text(
        f"✅ *Scan Stopped!*\n\n"
        f"📊 Scanned: {status_dict['scanned_ips']}/{status_dict['total_ips']} IPs\n"
        f"✅ Found: {status_dict['active_ips']} active IPs\n\n"
        f"_Partial results may be available_",
        parse_mode='Markdown'
    )

async def download_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /download command"""
    if not os.path.exists("ip.txt") and not os.path.exists("live_ips.txt"):
        await update.message.reply_text(
            "❌ *No Results Available!*\n\n"
            "No scan results found to download.\n"
            "Please run a scan first: /scan",
            parse_mode='Markdown'
        )
        return
    
    try:
        await update.message.reply_text(
            "📤 *Preparing Files...*\n\nSending scan results to you...",
            parse_mode='Markdown'
        )
        
        status_dict = scan_status.get_status_dict()
        files_sent = 0
        
        # Send detailed report
        if os.path.exists("ip.txt"):
            with open("ip.txt", "rb") as f:
                await update.message.reply_document(
                    document=f,
                    filename=f"detailed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    caption=f"📊 *Detailed Report*\n✅ {status_dict['active_ips']} Active IPs"
                )
                files_sent += 1
        
        # Send IP list
        if os.path.exists("live_ips.txt"):
            with open("live_ips.txt", "rb") as f:
                await update.message.reply_document(
                    document=f,
                    filename=f"ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    caption=f"📋 *IP List*\n✅ {status_dict['active_ips']} IPs"
                )
                files_sent += 1
        
        await update.message.reply_text(
            f"✅ *Files Sent!*\n\n📁 {files_sent} file(s) delivered successfully",
            parse_mode='Markdown'
        )
        
    except Exception as e:
        logger.error(f"Download error: {e}")
        await update.message.reply_text(
            f"❌ *Download Error*\n\n`{str(e)}`",
            parse_mode='Markdown'
        )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command"""
    help_text = """
📚 *CIDRProbe Bot - Help Guide*
━━━━━━━━━━━━━━━━━━━━━

*🤖 Commands:*

/scan <CIDR> - Start network scan
/status - Check scan progress
/history - View scan history
/download - Get latest results
/stop - Stop current scan
/help - Show this help

*📝 Examples:*

`/scan 192.168.1.0/24`
Scan local network (254 IPs)

`/scan 10.0.0.0/16`
Scan large network (65k IPs)

*✨ Features:*

🗄️ Auto file storage in bot
📂 Access scan history anytime
📥 Re-download old scans
✅ Reliable retry logic
🔔 Periodic progress updates
🛑 Stop scan anytime

*🔧 Technical Details:*

• Concurrent scanning (50 threads)
• Port scan: 12 common ports
• HTTP status detection
• Hostname resolution
• Cloud storage integration

*💡 Tips:*

1. Large scans take time
2. Check status regularly
3. Files auto-uploaded
4. History saved permanently

━━━━━━━━━━━━━━━━━━━━━
Need more help? Contact admin
    """
    
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline button callbacks"""
    query = update.callback_query
    await query.answer()
    
    if query.data == 'status':
        status_text = get_status_text()
        status_dict = scan_status.get_status_dict()
        
        keyboard = []
        if status_dict['is_scanning']:
            keyboard.append([InlineKeyboardButton("🔄 Refresh", callback_data='status')])
            keyboard.append([InlineKeyboardButton("🛑 Stop", callback_data='stop')])
        else:
            keyboard.append([InlineKeyboardButton("📂 History", callback_data='history')])
            keyboard.append([InlineKeyboardButton("🚀 New Scan", callback_data='scan_prompt')])
        
        reply_markup = InlineKeyboardMarkup(keyboard) if keyboard else None
        
        try:
            await query.edit_message_text(status_text, reply_markup=reply_markup, parse_mode='Markdown')
        except:
            await query.message.reply_text(status_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    elif query.data == 'history':
        scans = file_storage.get_all_scans()
        
        if not scans:
            await query.message.reply_text("📂 No scan history available")
            return
        
        history_text = f"📂 *SCAN HISTORY*\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        
        for i, (scan_id, data) in enumerate(scans[:10], 1):
            history_text += f"{i}. `{data['cidr']}` - {data['active_ips']} IPs\n"
            history_text += f"   📅 {data['date']}\n\n"
        
        keyboard = []
        for scan_id, data in scans[:5]:
            keyboard.append([InlineKeyboardButton(
                f"📥 {data['cidr']} ({data['active_ips']} IPs)",
                callback_data=f"getfile_{scan_id}"
            )])
        
        keyboard.append([InlineKeyboardButton("🔄 Refresh", callback_data='history')])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.message.reply_text(history_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    elif query.data.startswith('getfile_'):
        scan_id = query.data.replace('getfile_', '')
        
        scan_data = file_storage.get_scan(scan_id)
        if not scan_data:
            await query.message.reply_text("❌ Scan not found in storage!")
            return
        
        await query.message.reply_text(
            f"📤 *Retrieving files...*\n\n"
            f"🎯 CIDR: `{scan_data['cidr']}`\n"
            f"✅ IPs: {scan_data['active_ips']}",
            parse_mode='Markdown'
        )
        
        try:
            # Send detailed report
            await app_instance.bot.send_document(
                chat_id=query.message.chat_id,
                document=scan_data['detailed_file_id'],
                caption=f"📊 Detailed Report\n🎯 {scan_data['cidr']}\n✅ {scan_data['active_ips']} IPs",
                parse_mode='Markdown'
            )
            
            # Send IP list
            await app_instance.bot.send_document(
                chat_id=query.message.chat_id,
                document=scan_data['ip_list_file_id'],
                caption=f"📋 IP List\n🎯 {scan_data['cidr']}\n✅ {scan_data['active_ips']} IPs",
                parse_mode='Markdown'
            )
            
            await query.message.reply_text("✅ Files retrieved from storage successfully!")
            
        except Exception as e:
            logger.error(f"File retrieval error: {e}")
            await query.message.reply_text(f"❌ Error retrieving files: `{str(e)}`", parse_mode='Markdown')
    
    elif query.data == 'stop':
        if scan_status.get_status_dict()['is_scanning']:
            scan_status.stop_scan()
            await query.message.reply_text("🛑 Stopping scan...")
        else:
            await query.message.reply_text("ℹ️ No active scan to stop")
    
    elif query.data == 'download':
        class FakeUpdate:
            def __init__(self, message):
                self.message = message
        
        fake_update = FakeUpdate(query.message)
        await download_command(fake_update, context)
    
    elif query.data == 'help':
        await help_command(query, context)
    
    elif query.data == 'scan_prompt':
        await query.message.reply_text(
            "📝 *Start a new scan*\n\n"
            "Use this format:\n"
            "`/scan 192.168.1.0/24`\n\n"
            "🗄️ Results will be stored automatically!",
            parse_mode='Markdown'
        )

async def send_periodic_update(context: ContextTypes.DEFAULT_TYPE):
    """Send periodic scan updates (every 10 minutes)"""
    status_dict = scan_status.get_status_dict()
    
    if status_dict['is_scanning'] and status_dict['has_results'] and status_dict['chat_id']:
        try:
            chat_id = status_dict['chat_id']
            
            # Save current results
            save_scan_results()
            
            # Send update message
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"🔔 *10-MINUTE UPDATE*\n\n"
                     f"✅ Active IPs found: {status_dict['active_ips']}\n"
                     f"📊 Progress: {status_dict['scanned_ips']}/{status_dict['total_ips']}\n"
                     f"🔍 Current: `{status_dict['current_ip']}`",
                parse_mode='Markdown'
            )
            
            # Send interim results file
            if os.path.exists("ip.txt"):
                with open("ip.txt", "rb") as f:
                    await context.bot.send_document(
                        chat_id=chat_id,
                        document=f,
                        filename=f"interim_update_{datetime.now().strftime('%H%M')}.txt",
                        caption="📊 Interim scan results"
                    )
            
            scan_status.update_last_update_time()
            
        except Exception as e:
            logger.error(f"Periodic update error: {e}")

# ✅ Signal Handlers
def signal_handler(sig, frame):
    """Handle shutdown signals"""
    logger.info("🛑 Shutdown signal received")
    scan_status.stop_scan()
    logger.info("✅ Cleanup complete")
    sys.exit(0)

# ✅ Main Function
def main():
    """Main bot initialization and execution"""
    global app_instance
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("=" * 70)
    logger.info("🚀 Starting CIDRProbe Bot v5.1")
    logger.info("=" * 70)
    logger.info(f"📅 Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"🔧 Python version: {sys.version.split()[0]}")
    logger.info(f"🤖 Bot token configured: Yes")
    logger.info(f"👤 Admin chat ID: {ADMIN_CHAT_ID}")
    logger.info(f"🗄️ Storage chat ID: {STORAGE_CHAT_ID}")
    logger.info("=" * 70)
    
    # Create bot application
    application = Application.builder().token(BOT_TOKEN).build()
    app_instance = application
    
    # Register command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("scan", scan_command))
    application.add_handler(CommandHandler("stop", stop_command))
    application.add_handler(CommandHandler("download", download_command))
    application.add_handler(CommandHandler("history", history_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # Setup periodic updates (every 10 minutes)
    try:
        job_queue = application.job_queue
        if job_queue:
            job_queue.run_repeating(send_periodic_update, interval=600, first=600)
            logger.info("✅ Periodic updates enabled (10 minutes interval)")
    except Exception as e:
        logger.warning(f"⚠️ Could not setup periodic updates: {e}")
    
    logger.info("🤖 Bot initialized successfully!")
    logger.info("📡 Starting polling...")
    logger.info("=" * 70)
    
    # Start bot
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
