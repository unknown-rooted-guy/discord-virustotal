# Welcome to my VirusTotal Discord bot source code!

So this was created by @unknown-rooted-guy and some help from clanker because I don't fully know Discord library. I made this for myself since some shits are malware and I am scared to have viruses on my rooted phone since it can inject itself to kernel and yes.

Credits: Virustotal for api and detecting malwares, ChatGPT for helping me with discord library in python, Discord for being a great place for communities, And of course, Python developers for keeping this language alive.

# Requirements:

An operating system that have terminal (Android termux, Linux Distro, Windows and etc ig)
Minumum: Very patato PC/Laptop or phone with custom rom that has terminal or Android with termux
- 50 MB ram (100-150 MB recommended 🙏)
- 50 MB free space
- Network (HTTPS onbound)
- Linux kernel > 3.9
- glibc or musl both supported
- Python > 3.8 (3.10 recommended)
- 1 core with ARM or x86_64 CPU

# Installation

## 1. Install Python and Git

Debian/Ubuntu:

```Bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv
```

Arch Linux:

```Bash
sudo pacman -S python python-pip git
```

Alpine Linux:

```Bash
apk add python3 py3-pip git
```

Termux (Android):

```Bash
pkg update
pkg install python git
```

Windows:

```Bash
winget install git
```

- Download Python 3.10+
https://www.python.org/downloads/windows/
- Enable “Add Python to PATH”
- Open Command Prompt / PowerShell
Verify:

```Bash
python --version
```

## 1. Clone repository

```Bash
git clone https://github.com/yourname/vt-discord-bot.git
cd vt-discord-bot
```

## 3. (Optional but recommended) Virtual environment
Linux / Termux

```Bash
python -m venv venv
source venv/bin/activate
```

Windows

```Bat
python -m venv venv
venv\Scripts\activate
```

## 4. Install dependencies

```Bash
pip install -U discord.py aiohttp python-dotenv
```

## 5. Configure environment variables

Edit .env file:

```Bash
nano .env
```

Edit *your_discord_bot_token* with your Discord bot token, obtained in https://discord.com/developers/docs/intro. Also replace *your_virustotal_api_key* with your Virus Total api, obtained in https://www.virustotal.com/ and find the API key in there.

DISCORD_TOKEN=your_discord_bot_token
VT_API_KEY=your_virustotal_api_key

⚠️ - Do NOT share this with anyone, APIs and tokens must be secured and shared one with your trust.

## 6. Run the bot

```Bash
python vtbot.py
```

Expected output:

```Bash
VirusTotal bot ready
Slash commands will appear automatically after sync.
```

## 7. Common issues

Slash commands not showing
• Wait up to 1 minute
• Re-invite bot with applications.commands permission
Permission error on Linux

```Bash
pip install --user discord.py aiohttp python-dotenv
```

Low RAM devices
• Close background apps
• Avoid scanning large files
• Free VT API tier recommended

## 8. Update bot

```Bash
git pull
pip install -U discord.py aiohttp python-dotenv
```

# End of file

Congratulations, you just installed discord bot and ran it locally, there isn't one that is fully ran 24/7 because I don't have server, but yeah. Any contrubutions will be apprecieted, tested ones will be very useful, Any reports, bugs help, dm me in discord: @root_a505fn. Have a great day!
