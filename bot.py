import asyncio
import base64
import binascii
import io
import json
import logging
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import discord
from discord import app_commands


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("lua-sentinel")


MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", str(2 * 1024 * 1024)))
CONFIG_PATH = Path(os.getenv("CONFIG_PATH", "data/config.json"))
LUA_EXTENSIONS = {".lua", ".luau"}


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    evidence: str


@dataclass
class ScanResult:
    filename: str
    size: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return bool(self.findings)


def _env_channel_id(name: str) -> int | None:
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        log.warning("Ignoring invalid %s; expected a numeric Discord channel ID", name)
        return None


class ChannelConfig:
    def __init__(self, path: Path):
        self.path = path
        self.scan_channel_id = _env_channel_id("SCAN_CHANNEL_ID")
        self.report_channel_id = _env_channel_id("REPORT_CHANNEL_ID")
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            if self.scan_channel_id is None:
                self.scan_channel_id = int(saved["scan_channel_id"]) if saved.get("scan_channel_id") else None
            if self.report_channel_id is None:
                self.report_channel_id = int(saved["report_channel_id"]) if saved.get("report_channel_id") else None
        except (OSError, ValueError, TypeError, KeyError) as exc:
            log.warning("Could not load channel configuration: %s", exc)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {
                    "scan_channel_id": self.scan_channel_id,
                    "report_channel_id": self.report_channel_id,
                },
                indent=2,
            ),
            encoding="utf-8",
        )


config = ChannelConfig(CONFIG_PATH)


WEBHOOK_RE = re.compile(
    r"https?://(?:canary\.|ptb\.)?(?:discord(?:app)?\.com)/api/webhooks/\d{5,}/[A-Za-z0-9._-]+",
    re.IGNORECASE,
)
WEBHOOK_FRAGMENT_RE = re.compile(r"(?:discord(?:app)?\.com|discord\.gg).{0,80}(?:api|webhook)", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
LUA_STRING_RE = re.compile(r"""(['"])(.*?)(?<!\\)\1""", re.DOTALL)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/])")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{24,})(?![0-9A-Fa-f])")
DECIMAL_ESCAPE_RE = re.compile(r"\\([0-9]{1,3})")
HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")


KEYLOGGER_RULES: tuple[tuple[str, str, str, str], ...] = (
    ("high", "Keyboard API", r"\b(?:GetAsyncKeyState|GetKeyState|MapVirtualKey(?:A|W)?|RegisterRawInputDevices)\b", "Windows keyboard API"),
    ("high", "Lua keyboard hook", r"\b(?:keyboard|keylogger|key[_-]?log|onKeyDown|on_key_down|isKeyDown|keyDown)\b", "keyboard hook/keylogger indicator"),
    ("high", "Input capture", r"\b(?:io\.read|io\.lines|readfile|read_file|GetInput|InputBegan|UserInputService)\b", "input capture function"),
    ("medium", "Clipboard access", r"\b(?:clipboard|GetClipboardData|setclipboard|toclipboard)\b", "clipboard access indicator"),
    ("medium", "Data exfiltration", r"\b(?:HttpPost|HttpGet|PerformHttpRequest|request\s*\(|http\.request|curl|wget)\b", "network request indicator"),
    ("medium", "Process execution", r"\b(?:os\.execute|io\.popen|ShellExecute|CreateProcess)\b", "process execution indicator"),
)


def _unique(values: Iterable[str], limit: int = 5) -> list[str]:
    output: list[str] = []
    for value in values:
        clean = value.strip()
        if clean and clean not in output:
            output.append(clean[:240])
        if len(output) >= limit:
            break
    return output


def decode_lua_escapes(value: str) -> str:
    def decimal_replace(match: re.Match[str]) -> str:
        number = int(match.group(1))
        return chr(number) if number <= 255 else match.group(0)

    value = HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), value)
    return DECIMAL_ESCAPE_RE.sub(decimal_replace, value)


def compact(value: str) -> str:
    return re.sub(r"[\s_+%.\"'`\\]+", "", value).lower()


def safe_base64_decode(value: str) -> str | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded, validate=True)
        if not decoded or len(decoded) > 200_000:
            return None
        text = decoded.decode("utf-8", errors="ignore")
        return text if sum(char.isprintable() for char in text) / max(len(text), 1) > 0.75 else None
    except (binascii.Error, ValueError):
        return None


def build_search_material(source: str) -> list[str]:
    material = [source, decode_lua_escapes(source), urllib.parse.unquote(source)]
    strings = [decode_lua_escapes(match.group(2)) for match in LUA_STRING_RE.finditer(source)]
    material.extend(strings)

    for match in BASE64_RE.finditer(source):
        decoded = safe_base64_decode(match.group(1))
        if decoded:
            material.append(decoded)

    for match in HEX_RE.finditer(source):
        raw = match.group(1)
        try:
            decoded = bytes.fromhex(raw).decode("utf-8", errors="ignore")
            if decoded:
                material.append(decoded)
        except ValueError:
            continue

    # This catches webhook fragments assembled with Lua concatenation.
    material.append("".join(strings))
    material.append("".join(compact(item) for item in strings))
    return material


def scan_lua(filename: str, source: str) -> ScanResult:
    result = ScanResult(filename=filename, size=len(source.encode("utf-8", errors="ignore")))
    materials = build_search_material(source)
    combined = "\n".join(materials)
    compacted = compact(combined)

    webhook_matches = _unique(WEBHOOK_RE.findall(combined))
    if webhook_matches:
        result.findings.append(
            Finding("webhook", "critical", "Discord webhook URL ditemukan", "; ".join(webhook_matches))
        )
    elif WEBHOOK_FRAGMENT_RE.search(combined) or all(
        token in compacted for token in ("discord", "api", "webhook")
    ):
        result.findings.append(
            Finding(
                "webhook",
                "high",
                "Pola Discord webhook terdeteksi",
                "URL/potongan URL terlihat setelah normalisasi atau decoding",
            )
        )

    seen_rules: set[str] = set()
    for severity, title, pattern, evidence in KEYLOGGER_RULES:
        if re.search(pattern, combined, re.IGNORECASE) and title not in seen_rules:
            seen_rules.add(title)
            result.findings.append(Finding("keylogger", severity, title, evidence))

    # Escalate combinations commonly used to capture and send keystrokes.
    has_input = any(item.category == "keylogger" and item.title in {"Keyboard API", "Lua keyboard hook", "Input capture"} for item in result.findings)
    has_network = any(item.category == "keylogger" and item.title == "Data exfiltration" for item in result.findings)
    if has_input and has_network:
        result.findings.append(
            Finding("keylogger", "critical", "Kombinasi capture + network", "Input keyboard dan pengiriman jaringan muncul bersamaan")
        )

    return result


def result_embed(result: ScanResult) -> discord.Embed:
    if not result.findings:
        embed = discord.Embed(
            title="Pemeriksaan Lua: bersih dari pola yang dikenal",
            description="Tidak ada webhook Discord atau indikator keylogger yang cocok dengan aturan saat ini.",
            color=discord.Color.green(),
        )
    else:
        critical = any(item.severity == "critical" for item in result.findings)
        embed = discord.Embed(
            title="Pemeriksaan Lua: TEMUAN TERDETEKSI",
            description="File perlu ditinjau manual. Hasil ini adalah indikator, bukan bukti pasti malware.",
            color=discord.Color.red() if critical else discord.Color.orange(),
        )
        for index, item in enumerate(result.findings[:10], start=1):
            embed.add_field(
                name=f"{index}. [{item.severity.upper()}] {item.title}",
                value=f"{item.category}: {item.evidence}",
                inline=False,
            )

    embed.add_field(name="File", value=result.filename[:100], inline=True)
    embed.add_field(name="Ukuran", value=f"{result.size:,} byte", inline=True)
    embed.set_footer(text="Lua Sentinel • static analysis only")
    return embed


class LuaSentinel(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self) -> None:
        synced = await self.tree.sync()
        log.info("Synced %d application commands", len(synced))

    async def on_ready(self) -> None:
        log.info("Logged in as %s (%s)", self.user, self.user.id if self.user else "?")

    async def on_message(self, message: discord.Message) -> None:
        if message.author.bot:
            return
        if config.scan_channel_id is None or message.channel.id != config.scan_channel_id:
            return
        lua_attachments = [
            attachment
            for attachment in message.attachments
            if Path(attachment.filename).suffix.lower() in LUA_EXTENSIONS
        ]
        if not lua_attachments:
            return

        report_channel = self.get_channel(config.report_channel_id) if config.report_channel_id else message.channel
        if not isinstance(report_channel, discord.TextChannel):
            log.warning("Report channel is missing or not a text channel")
            return

        for attachment in lua_attachments:
            if attachment.size > MAX_FILE_BYTES:
                await report_channel.send(
                    f"File `{attachment.filename}` dilewati: ukuran {attachment.size:,} byte melebihi batas {MAX_FILE_BYTES:,} byte."
                )
                continue
            try:
                data = await attachment.read()
                source = data.decode("utf-8", errors="replace")
                result = scan_lua(attachment.filename, source)
                embed = result_embed(result)
                embed.add_field(name="Pengirim", value=message.author.mention, inline=True)
                embed.add_field(name="Pesan", value=f"[buka pesan]({message.jump_url})", inline=True)
                await report_channel.send(embed=embed)
            except (discord.HTTPException, discord.NotFound, UnicodeError) as exc:
                log.warning("Could not scan %s: %s", attachment.filename, exc)


client = LuaSentinel()


def admin_only(interaction: discord.Interaction) -> bool:
    return isinstance(interaction.user, discord.Member) and interaction.user.guild_permissions.manage_channels


@client.tree.command(name="set-scan-channel", description="Tetapkan channel tempat file Lua diperiksa")
@app_commands.describe(channel="Channel untuk upload file Lua")
async def set_scan_channel(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
    if not admin_only(interaction):
        await interaction.response.send_message("Perlu izin Manage Channels.", ephemeral=True)
        return
    config.scan_channel_id = channel.id
    config.save()
    await interaction.response.send_message(
        f"Channel pemeriksaan ditetapkan ke {channel.mention}. Upload file .lua/.luau di sana.",
        ephemeral=True,
    )


@client.tree.command(name="set-report-channel", description="Tetapkan channel tujuan laporan hasil scan")
@app_commands.describe(channel="Channel untuk menerima laporan")
async def set_report_channel(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
    if not admin_only(interaction):
        await interaction.response.send_message("Perlu izin Manage Channels.", ephemeral=True)
        return
    config.report_channel_id = channel.id
    config.save()
    await interaction.response.send_message(
        f"Channel laporan ditetapkan ke {channel.mention}.",
        ephemeral=True,
    )


@client.tree.command(name="scan", description="Scan file Lua yang dilampirkan langsung pada perintah ini")
@app_commands.describe(file="File .lua atau .luau yang ingin diperiksa")
async def scan_command(interaction: discord.Interaction, file: discord.Attachment) -> None:
    if Path(file.filename).suffix.lower() not in LUA_EXTENSIONS:
        await interaction.response.send_message("Hanya file .lua atau .luau yang didukung.", ephemeral=True)
        return
    if file.size > MAX_FILE_BYTES:
        await interaction.response.send_message("File melebihi batas ukuran scan.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    data = await file.read()
    result = scan_lua(file.filename, data.decode("utf-8", errors="replace"))
    await interaction.followup.send(embed=result_embed(result), ephemeral=True)


async def main() -> None:
    token = os.getenv("DISCORD_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("DISCORD_BOT_TOKEN belum diatur")
    await client.start(token)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Bot stopped")