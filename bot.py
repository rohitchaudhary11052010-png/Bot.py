import asyncio
import logging
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
import requests
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    filters,
    ContextTypes
)
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson import ObjectId
import re
from functools import wraps
import html
import uuid
import os
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
MONGODB_URI = os.getenv("MONGODB_URI") or os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "attack_bot")
API_URL = os.getenv("API_URL")
API_KEY = os.getenv("API_KEY")

# Admin IDs safely parsing
try:
    ADMIN_IDS = [int(id.strip()) for id in os.getenv("ADMIN_IDS", "1793697840").split(",") if id.strip().isdigit()]
except Exception:
    ADMIN_IDS = [1793697840]

# Blocked ports (must match backend)
BLOCKED_PORTS = {8700, 20000, 443, 17500, 9031, 20002, 20001}

# Allowed port range
MIN_PORT = 1
MAX_PORT = 65535

# Helper function to make datetime timezone-aware
def make_aware(dt):
    """Convert naive datetime to timezone-aware UTC datetime"""
    if dt is None:
        return None
    if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def get_current_time():
    """Get current UTC time with timezone"""
    return datetime.now(timezone.utc)

def escape_markdown(text: str) -> str:
    """Escape special characters for MarkdownV2"""
    if not text:
        return ""
    special_chars = r'_*[]()~`>#+-=|{}.!'
    return ''.join(f'\\{char}' if char in special_chars else char for char in str(text))

# MongoDB Connection
class Database:
    def __init__(self):
        if not MONGODB_URI:
            logger.critical("❌ MONGODB_URI is missing in environment variables!")
            raise ValueError("MONGODB_URI environments variable missing setup.")
            
        self.client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        self.db = self.client[DATABASE_NAME]
        self.users = self.db.users
        self.attacks = self.db.attacks
        
        # Test connection status
        try:
            self.client.admin.command('ping')
            logger.info("✅ MongoDB ping status: Connected successfully.")
        except Exception as e:
            logger.critical(f"❌ Connection refused to MongoDB server: {e}")
            raise e
        
        # Clean up any documents with null user_id
        try:
            result = self.users.delete_many({"user_id": None})
            if result.deleted_count > 0:
                logger.info(f"Deleted {result.deleted_count} documents with null user_id")
            
            result = self.users.delete_many({"user_id": {"$exists": False}})
            if result.deleted_count > 0:
                logger.info(f"Deleted {result.deleted_count} documents without user_id")
        except Exception as e:
            logger.error(f"Error cleaning users collection: {e}")
        
        # Drop existing indexes safely using try-except block to ignore non-existent index errors
        try:
            self.users.drop_indexes()
            logger.info("Dropped existing indexes from users collection cleanly")
        except Exception as e:
            logger.info(f"Handled users collection index cleanup: {e}")
        
        try:
            self.attacks.drop_indexes()
            logger.info("Dropped existing indexes from attacks collection cleanly")
        except Exception as e:
            logger.info(f"Handled attacks collection index cleanup: {e}")
        
        # Create new indexes for attacks collection
        try:
            self.attacks.create_index([("timestamp", DESCENDING)])
            self.attacks.create_index([("user_id", ASCENDING)])
            self.attacks.create_index([("status", ASCENDING)])
            logger.info("Created indexes for attacks collection")
        except Exception as e:
            logger.error(f"Error creating attacks indexes: {e}")
        
        # Create unique index on user_id for users collection
        try:
            self.users.create_index([("user_id", ASCENDING)], unique=True, sparse=True)
            logger.info("Created unique index on user_id for users collection")
        except Exception as e:
            logger.error(f"Error creating users index: {e}")
        
    def get_user(self, user_id: int) -> Optional[Dict]:
        user = self.users.find_one({"user_id": user_id})
        if user:
            if user.get("created_at"): user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"): user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"): user["expires_at"] = make_aware(user["expires_at"])
        return user
    
    def create_user(self, user_id: int, username: str = None) -> Dict:
        existing_user = self.get_user(user_id)
        if existing_user:
            return existing_user
            
        user_data = {
            "user_id": user_id,
            "username": username,
            "approved": False,
            "approved_at": None,
            "expires_at": None,
            "total_attacks": 0,
            "created_at": get_current_time(),
            "is_banned": False
        }
        try:
            self.users.insert_one(user_data)
            logger.info(f"Created new user: {user_id}")
        except pymongo.errors.DuplicateKeyError:
            user_data = self.get_user(user_id)
            logger.info(f"User {user_id} already exists")
        except Exception as e:
            logger.error(f"Error creating user: {e}")
        return user_data
    
    def approve_user(self, user_id: int, days: int) -> bool:
        expires_at = get_current_time() + timedelta(days=days)
        result = self.users.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "approved": True,
                    "approved_at": get_current_time(),
                    "expires_at": expires_at
                }
            }
        )
        return result.modified_count > 0
    
    def disapprove_user(self, user_id: int) -> bool:
        result = self.users.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "approved": False,
                    "expires_at": None
                }
            }
        )
        return result.modified_count > 0
    
    def log_attack(self, user_id: int, ip: str, port: int, duration: int, status: str, response: str = None):
        attack_data = {
            "_id": str(uuid.uuid4()),
            "user_id": user_id,
            "ip": ip,
            "port": port,
            "duration": duration,
            "status": status,
            "response": response[:500] if response else None,
            "timestamp": get_current_time()
        }
        try:
            self.attacks.insert_one(attack_data)
            self.users.update_one(
                {"user_id": user_id},
                {"$inc": {"total_attacks": 1}}
            )
            logger.info(f"Logged attack for user {user_id}: {status}")
        except Exception as e:
            logger.error(f"Failed to log attack: {e}")
    
    def get_all_users(self) -> List[Dict]:
        users = list(self.users.find({"user_id": {"$ne": None, "$exists": True}}))
        for user in users:
            if user.get("created_at"): user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"): user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"): user["expires_at"] = make_aware(user["expires_at"])
            if "total_attacks" not in user: user["total_attacks"] = 0
        return users
    
    def get_approved_users(self) -> List[Dict]:
        users = list(self.users.find({"approved": True, "is_banned": False, "user_id": {"$ne": None}}))
        for user in users:
            if user.get("created_at"): user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"): user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"): user["expires_at"] = make_aware(user["expires_at"])
        return users
    
    def get_user_attack_stats(self, user_id: int) -> Dict:
        total_attacks = self.attacks.count_documents({"user_id": user_id})
        successful_attacks = self.attacks.count_documents({"user_id": user_id, "status": "success"})
        failed_attacks = self.attacks.count_documents({"user_id": user_id, "status": "failed"})
        
        recent_attacks = list(self.attacks.find({"user_id": user_id}).sort("timestamp", -1).limit(10))
        for attack in recent_attacks:
            if attack.get("timestamp"):
                attack["timestamp"] = make_aware(attack["timestamp"])
        
        return {
            "total": total_attacks,
            "successful": successful_attacks,
            "failed": failed_attacks,
            "recent": recent_attacks
        }

# Initialize database safely
print("🔄 Initializing database connection...")
db = Database()
print("✅ Database initialized successfully!")

def is_port_blocked(port: int) -> bool:
    return port in BLOCKED_PORTS

def get_blocked_ports_list() -> str:
    return ", ".join(str(port) for port in sorted(BLOCKED_PORTS))

def admin_required(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in ADMIN_IDS:
            await update.message.reply_text("❌ You are not authorized to use this command.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper

async def is_user_approved(user_id: int) -> bool:
    user = db.get_user(user_id)
    if not user or not user.get("approved", False):
        return False
    
    expires_at = user.get("expires_at")
    if expires_at:
        expires_at = make_aware(expires_at)
        if expires_at < get_current_time():
            return False
    return True

# API Calls
def check_api_health() -> Dict:
    try:
        response = requests.get(f"{API_URL}/api/v1/health", headers={"x-api-key": API_KEY, "Content-Type": "application/json"}, timeout=10)
        return response.json() if response.status_code == 200 else {"status": "error", "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def check_running_attacks() -> Dict:
    try:
        response = requests.get(f"{API_URL}/api/v1/active", headers={"x-api-key": API_KEY, "Content-Type": "application/json"}, timeout=10)
        return response.json() if response.status_code == 200 else {"success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_user_stats() -> Dict:
    try:
        response = requests.get(f"{API_URL}/api/v1/stats", headers={"x-api-key": API_KEY, "Content-Type": "application/json"}, timeout=10)
        return response.json() if response.status_code == 200 else {"success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def launch_attack(ip: str, port: int, duration: int) -> Dict:
    try:
        response = requests.post(f"{API_URL}/api/v1/attack", json={"ip": ip, "port": port, "duration": duration}, headers={"x-api-key": API_KEY, "Content-Type": "application/json"}, timeout=15)
        return response.json()
    except Exception as e:
        return {"error": str(e), "success": False}

# Command Handlers
@admin_required
async def approve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if len(context.args) < 2:
            await update.message.reply_text("❌ Usage: /approve <user_id> <days>")
            return
        user_id = int(context.args[0])
        days = int(context.args[1])
        if days <= 0:
            await update.message.reply_text("❌ Days must be positive.")
            return
        db.create_user(user_id)
        if db.approve_user(user_id, days):
            expires_at = get_current_time() + timedelta(days=days)
            await update.message.reply_text(f"✅ User {user_id} approved for {days} days!\n📅 Expires on: {expires_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

@admin_required
async def disapprove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if len(context.args) < 1:
            await update.message.reply_text("❌ Usage: /disapprove <user_id>")
            return
        user_id = int(context.args[0])
        if db.disapprove_user(user_id):
            await update.message.reply_text(f"✅ User {user_id} has been disapproved.")
        else:
            await update.message.reply_text("❌ Failed to disapprove user.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

@admin_required
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    status_msg = await update.message.reply_text("🔄 Checking API health status...")
    health = check_api_health()
    if health.get("status") == "ok":
        message = f"✅ API Status: Healthy\n\n🌐 API URL: {API_URL}"
    else:
        message = f"❌ API Status: Unhealthy\n\nError: {health.get('error', 'Unknown error')}"
    await status_msg.edit_text(message)

@admin_required
async def running_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    status_msg = await update.message.reply_text("🔄 Fetching active attacks...")
    attacks = check_running_attacks()
    if attacks.get("success"):
        active_attacks = attacks.get("activeAttacks", [])
        if active_attacks:
            message = f"🎯 Active Attacks ({len(active_attacks)})\n\n"
            for attack in active_attacks:
                message += f"🔹 Target: {attack['target']}:{attack['port']}\n   ⏱️ Expires in: {attack['expiresIn']}s\n\n"
        else:
            message = "✅ No active attacks running."
    else:
        message = f"❌ Error: {attacks.get('error', 'Unknown error')}"
    await status_msg.edit_text(message)

@admin_required
async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        users = db.get_all_users()
        if not users:
            await update.message.reply_text("📭 No users found.")
            return
        approved_count = sum(1 for u in users if u.get("approved", False))
        message = f"👥 Total Users: {len(users)}\n✅ Approved Users: {approved_count}\n\n📋 List (Top 10):\n"
        for idx, user in enumerate(users[:10], 1):
            user_id = user.get('user_id', 'Unknown')
            status = "✅" if user.get("approved", False) else "❌"
            message += f"{idx}. {user_id} {status} - {user.get('total_attacks', 0)} attacks\n"
        await update.message.reply_text(message)
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

@admin_required
async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        users = db.get_all_users()
        total_attacks = sum(u.get("total_attacks", 0) for u in users)
        message = f"📊 Bot Stats:\n👥 Users: {len(users)}\n🎯 Total Attacks Logged: {total_attacks}"
        await update.message.reply_text(message)
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

@admin_required
async def blocked_ports_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(f"🚫 Blocked Ports:\n{get_blocked_ports_list()}")

# User commands
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    username = update.effective_user.username
    db.create_user(user_id, username)
    
    # 🔥 AUTOMATIC ADMIN APPROVAL: Agar aap admin ho, toh database me khud ko automatic approve kar do
    if user_id in ADMIN_IDS:
        db.approve_user(user_id, days=3650) # 10 saal ke liye automatic approve
        
    if await is_user_approved(user_id):
        await update.message.reply_text(f"✅ Welcome back, Admin! Your account is active.\nUse /help to see all commands.")
    else:
        await update.message.reply_text("❌ Access Denied! Please contact the administrator for approval.")
        

async def attack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ Access Denied!")
        return
    if len(context.args) != 3:
        await update.message.reply_text("❌ Usage: /attack <ip> <port> <duration>")
        return
        
    ip, port_str, duration_str = context.args[0], context.args[1], context.args[2]
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        await update.message.reply_text("❌ Invalid IP layout.")
        return
        
    try:
        port = int(port_str)
        duration = int(duration_str)
        if port < MIN_PORT or port > MAX_PORT or is_port_blocked(port):
            await update.message.reply_text("❌ Port invalid or blocked.")
            return
        if duration < 1 or duration > 300:
            await update.message.reply_text("❌ Duration limit: 1-300s.")
            return
    except ValueError:
        await update.message.reply_text("❌ Port/Duration must be numeric numbers.")
        return

    status_msg = await update.message.reply_text("🎯 Deploying attack stream...")
    response = launch_attack(ip, port, duration)
    
    if response.get("success"):
        db.log_attack(user_id, ip, port, duration, "success", str(response))
        await status_msg.edit_text(f"✅ Attack Success on {ip}:{port} for {duration} seconds!")
    else:
        db.log_attack(user_id, ip, port, duration, "failed", str(response))
        await status_msg.edit_text(f"❌ Failed: {response.get('error', 'API Response Refused')}")

async def myattacks_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await running_command(update, context)

async def myinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = db.get_user(update.effective_user.id)
    if user:
        status = "Approved" if user.get("approved") else "Pending Approval"
        await update.message.reply_text(f"🆔 ID: {user['user_id']}\n⚡ Status: {status}\n📊 Logged Attacks: {user.get('total_attacks', 0)}")

async def mystats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    stats = db.get_user_attack_stats(update.effective_user.id)
    await update.message.reply_text(f"📊 Your Stats:\nTotal: {stats['total']}\nSuccess: {stats['successful']}\nFailed: {stats['failed']}")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🤖 Commands List:\n/start - Verify Access\n/attack <ip> <port> <time> - Launch\n/myinfo - Check Account Status\n/mystats - Statistics")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Update {update} triggered error {context.error}")

def main():
    if not BOT_TOKEN:
        logger.critical("❌ BOT_TOKEN is missing!")
        return

    application = Application.builder().token(BOT_TOKEN).build()
    
    # Map command handlers
    application.add_handler(CommandHandler("approve", approve_command))
    application.add_handler(CommandHandler("disapprove", disapprove_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("running", running_command))
    application.add_handler(CommandHandler("users", users_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("blockedports", blocked_ports_command))
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("attack", attack_command))
    application.add_handler(CommandHandler("myattacks", myattacks_command))
    application.add_handler(CommandHandler("myinfo", myinfo_command))
    application.add_handler(CommandHandler("mystats", mystats_command))
    
    application.add_error_handler(error_handler)
    
    print("🚀 Telegram Bot engine deployed successfully. Running Polling...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
