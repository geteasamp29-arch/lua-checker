import asyncio
import ast
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
WEBHOOK_PATH_RE = re.compile(
    r"(?:discord(?:app)?\.com|discord\.gg)[^\s\"'<>]{0,120}(?:api|webhooks?)",
    re.IGNORECASE,
)
LUA_STRING_RE = re.compile(r"""(['"])(.*?)(?<!\\)\1""", re.DOTALL)
LUA_LONG_STRING_RE = re.compile(r"\[\[(.*?)\]\]", re.DOTALL)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{20,}={0,2})(?![A-Za-z0-9+/_-])")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{24,})(?![0-9A-Fa-f])")
DECIMAL_ESCAPE_RE = re.compile(r"\\([0-9]{1,3})")
HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")
LUA_CHAR_CALL_RE = re.compile(
    r"\b(?:string|utf8)\s*\.\s*char\s*\(([^()\n]{1,4000})\)",
    re.IGNORECASE,
)
LUA_ASSIGNMENT_RE = re.compile(
    r"(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;\n]+)",
    re.IGNORECASE,
)
LUA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LUA_LITERAL_RE = re.compile(r"""^\s*(['"])(.*?)(?<!\\)\1\s*$""", re.DOTALL)
LUA_LONG_LITERAL_RE = re.compile(r"^\s*\[\[(.*?)\]\]\s*$", re.DOTALL)
LUA_REVERSE_RE = re.compile(r"\bstring\s*\.\s*reverse\s*\(([^)]{1,2000})\)", re.IGNORECASE)
LUA_DYNAMIC_CODE_RE = re.compile(
    r"\b(?:loadstring|loadfile|dofile|load)\s*\(|\bassert\s*\(\s*(?:load|string\.char|utf8\.char)",
    re.IGNORECASE,
)
LUA_OBFUSCATION_RE = re.compile(
    r"\b(?:string|utf8)\s*\.\s*char\b|\b(?:table\s*\.\s*concat|string\s*\.\s*reverse)\b"
    r"|\b(?:bit32?|bit)\s*\.\s*(?:bxor|band|bor|lshift|rshift)\b",
    re.IGNORECASE,
)


KEYLOGGER_RULES: tuple[tuple[str, str, str, str], ...] = (
    (
        "high",
        "Keyboard API",
        r"\b(?:GetAsyncKeyState|GetKeyState|MapVirtualKey(?:A|W)?|RegisterRawInputDevices|"
        r"GetRawInputData|SetWindowsHookEx(?:A|W)?|WH_KEYBOARD_LL|keyboard\.is_pressed|pynput)\b",
        "Windows or library keyboard API",
    ),
    (
        "high",
        "Lua keyboard hook",
        r"\b(?:keyboard|keylogger|key[_-]?log|onKeyDown|on_key_down|onkeypress|"
        r"isKeyDown|keyDown|KeyPressed|KeyboardInput|InputBegan)\b",
        "keyboard hook/keylogger indicator",
    ),
    (
        "high",
        "Input capture",
        r"\b(?:io\.read|io\.lines|readfile|read_file|GetInput|UserInputService|"
        r"GetForegroundWindow|GetWindowText(?:A|W)?)\b",
        "input capture or active-window indicator",
    ),
    (
        "high",
        "Clipboard access",
        r"\b(?:clipboard|GetClipboardData|OpenClipboard|setclipboard|toclipboard|"
        r"readclipboard|writeclipboard)\b",
        "clipboard access indicator",
    ),
    (
        "high",
        "Screen capture",
        r"\b(?:screenshot|screen[_-]?capture|BitBlt|PrintWindow|CaptureScreen|"
        r"getScreenImage|takeScreenshot)\b",
        "screen capture indicator",
    ),
    (
        "medium",
        "Data exfiltration",
        r"\b(?:HttpPost|HttpGet|PerformHttpRequest|request\s*\(|http\.request|"
        r"curl|wget|fetch\s*\(|webhook)\b",
        "network request or webhook indicator",
    ),
    (
        "medium",
        "File/data storage",
        r"\b(?:io\.open|writefile|appendfile|readfile|savefile|json\.encode|"
        r"localStorage|sqlite|database)\b",
        "local storage or data collection indicator",
    ),
    (
        "high",
        "Process execution",
        r"\b(?:os\.execute|io\.popen|ShellExecute|CreateProcess|spawn\s*\(|"
        r"subprocess|powershell|cmd\.exe)\b",
        "process execution indicator",
    ),
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
    replacements = {
        r"\n": "\n",
        r"\r": "\r",
        r"\t": "\t",
        r"\b": "\b",
        r"\f": "\f",
        r"\v": "\v",
        r"\a": "\a",
        r"\0": "\0",
        r"\\": "\\",
        r"\"": '"',
        r"\'": "'",
    }

    # Lua's \z escape removes following whitespace, which is often used to
    # hide a URL across multiple source lines.
    value = re.sub(r"\\z\s*", "", value)
    for escaped, decoded in replacements.items():
        value = value.replace(escaped, decoded)
    value = value.replace(r"\/", "/")

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
        decoded = base64.urlsafe_b64decode(padded)
        if not decoded or len(decoded) > 200_000:
            return None
        text = decoded.decode("utf-8", errors="ignore")
        return text if sum(char.isprintable() for char in text) / max(len(text), 1) > 0.75 else None
    except (binascii.Error, ValueError):
        return None


def _split_top_level(value: str, separator: str = "..") -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(value):
        char = value[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and value.startswith(separator, index):
            parts.append(value[start:index])
            index += len(separator)
            start = index
            continue
        index += 1
    parts.append(value[start:])
    return parts


def _safe_int_expression(expression: str) -> int | None:
    """Evaluate only integer literals and basic arithmetic for string.char."""
    expression = expression.strip().replace("^", "**")
    expression = re.sub(r"(?i)0x([0-9a-f]+)", r"0x\1", expression)
    if len(expression) > 80 or not re.fullmatch(r"[0-9A-Fa-fxX\s()+\-*/%|&<>*]+", expression):
        return None
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return None

    def visit(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)):
            value = visit(node.operand)
            return value if isinstance(node.op, ast.UAdd) else (-value if isinstance(node.op, ast.USub) else ~value)
        if isinstance(node, ast.BinOp) and isinstance(
            node.op,
            (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Div, ast.Mod, ast.BitOr, ast.BitAnd, ast.BitXor, ast.LShift, ast.RShift),
        ):
            left = visit(node.left)
            right = visit(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, (ast.FloorDiv, ast.Div)):
                return left // right
            if isinstance(node.op, ast.Mod):
                return left % right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitAnd):
                return left & right
            if isinstance(node.op, ast.BitXor):
                return left ^ right
            if isinstance(node.op, ast.LShift):
                return left << right
            return left >> right
        raise ValueError("unsupported expression")

    try:
        return visit(tree)
    except (ValueError, ZeroDivisionError, OverflowError):
        return None


def decode_lua_char_calls(source: str) -> list[str]:
    decoded_values: list[str] = []
    for match in LUA_CHAR_CALL_RE.finditer(source):
        values: list[str] = []
        valid = True
        for argument in _split_top_level(match.group(1), separator=","):
            number = _safe_int_expression(argument)
            if number is None or not 0 <= number <= 255:
                valid = False
                break
            values.append(chr(number))
        if valid and values:
            decoded_values.append("".join(values))
    return decoded_values


def _literal_value(expression: str) -> str | None:
    expression = expression.strip()
    while expression.startswith("(") and expression.endswith(")"):
        expression = expression[1:-1].strip()
    match = LUA_LITERAL_RE.match(expression)
    if match:
        return decode_lua_escapes(match.group(2))
    match = LUA_LONG_LITERAL_RE.match(expression)
    return match.group(1) if match else None


def extract_static_assignments(source: str) -> list[str]:
    """Resolve simple local a = 'x' .. b chains without executing Lua."""
    assignments = LUA_ASSIGNMENT_RE.findall(source)
    known: dict[str, str] = {}
    values: list[str] = []
    for _ in range(6):
        changed = False
        for name, expression in assignments:
            expression = re.sub(
                r"\b(?:string|utf8)\s*\.\s*char\s*\(([^()\n]{1,4000})\)",
                lambda match: repr("".join(
                    chr(number)
                    for argument in _split_top_level(match.group(1), separator=",")
                    if (number := _safe_int_expression(argument)) is not None and 0 <= number <= 255
                )),
                expression,
                flags=re.IGNORECASE,
            )
            parts = _split_top_level(expression)
            resolved: list[str] = []
            valid = True
            for part in parts:
                literal = _literal_value(part)
                if literal is not None:
                    resolved.append(literal)
                elif LUA_IDENTIFIER_RE.fullmatch(part.strip()) and part.strip() in known:
                    resolved.append(known[part.strip()])
                else:
                    valid = False
                    break
            if valid and resolved:
                combined = "".join(resolved)
                if known.get(name) != combined:
                    known[name] = combined
                    values.append(combined)
                    changed = True
        if not changed:
            break
    return values


def build_search_material(source: str) -> list[str]:
    material: list[str] = [source, decode_lua_escapes(source), urllib.parse.unquote(source)]
    material.extend(decode_lua_char_calls(source))
    material.extend(extract_static_assignments(source))

    strings = [
        decode_lua_escapes(match.group(2))
        for match in LUA_STRING_RE.finditer(source)
    ]
    strings.extend(match.group(1) for match in LUA_LONG_STRING_RE.finditer(source))
    material.extend(strings)

    for match in LUA_REVERSE_RE.finditer(source):
        literal = _literal_value(match.group(1))
        if literal:
            material.append(literal[::-1])

    # Decode several layers, but keep the process bounded and never execute
    # decoded Lua. This is safe for files uploaded by untrusted users.
    for _ in range(3):
        new_values: list[str] = []
        for current in list(material):
            decoded_url = urllib.parse.unquote(current)
            if decoded_url != current:
                new_values.append(decoded_url)
            for match in BASE64_RE.finditer(current):
                decoded = safe_base64_decode(match.group(1))
                if decoded:
                    new_values.append(decoded)
            for match in HEX_RE.finditer(current):
                raw = match.group(1)
                try:
                    decoded = bytes.fromhex(raw).decode("utf-8", errors="ignore")
                except ValueError:
                    decoded = ""
                if decoded:
                    new_values.append(decoded)
        if not new_values:
            break
        material.extend(new_values)

    # Detect reversed fragments and strings assembled through concatenation.
    material.extend(item[::-1] for item in list(material) if len(item) <= 200_000)
    material.append("".join(strings))
    material.append("".join(compact(item) for item in strings))

    unique: list[str] = []
    seen: set[str] = set()
    for item in material:
        if item and item not in seen:
            seen.add(item)
            unique.append(item[:200_000])
        if len(unique) >= 2500:
            break
    return unique


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
    elif WEBHOOK_PATH_RE.search(combined) or (
        "discord" in compacted and "webhook" in compacted and "api" in compacted
    ):
        result.findings.append(
            Finding(
                "webhook",
                "high",
                "Pola Discord webhook terdeteksi setelah normalisasi/decoding",
                "Potongan URL atau komponen webhook ditemukan",
            )
        )

    seen_rules: set[str] = set()
    for severity, title, pattern, evidence in KEYLOGGER_RULES:
        if re.search(pattern, combined, re.IGNORECASE) and title not in seen_rules:
            seen_rules.add(title)
            result.findings.append(Finding("keylogger", severity, title, evidence))

    if LUA_DYNAMIC_CODE_RE.search(source):
        result.findings.append(
            Finding(
                "obfuscation",
                "critical",
                "Eksekusi kode dinamis",
                "load/loadstring/loadfile/dofile dapat menyembunyikan perilaku saat runtime",
            )
        )
    elif LUA_OBFUSCATION_RE.search(source):
        result.findings.append(
            Finding(
                "obfuscation",
                "medium",
                "Teknik obfuscation terdeteksi",
                "string.char/table.concat/string.reverse/bitwise decoder ditemukan",
            )
        )

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
