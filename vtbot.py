import os
import asyncio
import hashlib
import aiohttp
import discord
from discord import app_commands
from dotenv import load_dotenv

# Load secrets
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

if not DISCORD_TOKEN or not VT_API_KEY:
    raise SystemExit("Missing API keys in .env")

VT_HEADERS = {"x-apikey": VT_API_KEY}

intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

async def vt_get(url):
    async with aiohttp.ClientSession(headers=VT_HEADERS) as s:
        async with s.get(url) as r:
            return await r.json()

async def vt_post(url, data):
    async with aiohttp.ClientSession(headers=VT_HEADERS) as s:
        async with s.post(url, data=data) as r:
            return await r.json()

@client.event
async def on_ready():
    await tree.sync()
    print("VirusTotal bot ready")

# -------- URL SCAN --------
@tree.command(name="url", description="Scan a URL with VirusTotal")
async def scan_url(interaction: discord.Interaction, url: str):
    await interaction.response.defer(thinking=True)

    submit = await vt_post(
        "https://www.virustotal.com/api/v3/urls",
        {"url": url}
    )

    scan_id = submit["data"]["id"]
    await asyncio.sleep(20)

    result = await vt_get(
        f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    )

    stats = result["data"]["attributes"]["stats"]

    await interaction.followup.send(
        f"**URL Scan Result**\n"
        f"Malicious: {stats['malicious']}\n"
        f"Suspicious: {stats['suspicious']}\n"
        f"Harmless: {stats['harmless']}\n"
        f"Undetected: {stats['undetected']}"
    )

# -------- FILE SCAN --------
@tree.command(name="file", description="Scan an uploaded file with VirusTotal")
async def scan_file(
    interaction: discord.Interaction,
    file: discord.Attachment
):
    await interaction.response.defer(thinking=True)

    path = f"/data/data/com.termux/files/home/{file.filename}"
    await file.save(path)

    with open(path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    # Check existing hash
    check = await vt_get(
        f"https://www.virustotal.com/api/v3/files/{sha256}"
    )

    if "data" in check:
        stats = check["data"]["attributes"]["last_analysis_stats"]
        return await interaction.followup.send(
            f"**File already known**\n"
            f"Malicious: {stats['malicious']}\n"
            f"Suspicious: {stats['suspicious']}\n"
            f"Harmless: {stats['harmless']}\n"
            f"Undetected: {stats['undetected']}"
        )

    # Upload new file
    async with aiohttp.ClientSession(headers=VT_HEADERS) as s:
        data = aiohttp.FormData()
        data.add_field(
            "file",
            open(path, "rb"),
            filename=file.filename
        )
        async with s.post(
            "https://www.virustotal.com/api/v3/files",
            data=data
        ) as r:
            upload = await r.json()

    scan_id = upload["data"]["id"]
    await asyncio.sleep(30)

    result = await vt_get(
        f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    )
    stats = result["data"]["attributes"]["stats"]

    await interaction.followup.send(
        f"**File Scan Result**\n"
        f"Malicious: {stats['malicious']}\n"
        f"Suspicious: {stats['suspicious']}\n"
        f"Harmless: {stats['harmless']}\n"
        f"Undetected: {stats['undetected']}"
    )

client.run(DISCORD_TOKEN)
