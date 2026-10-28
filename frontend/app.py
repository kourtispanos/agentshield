"""AgentShield desktop app.

A plain window so anyone - no terminal needed - can talk to the local model and
watch the firewall work: every tool the agent runs shows up on the right, green
when allowed, red when blocked. The defenses are always on.

Run it with:  python frontend/app.py
"""

import getpass
import math
import os
import random
import re
import sys
import threading
import time
from urllib.error import URLError

# Emoji render as empty boxes in Kivy's default font, so strip them from chat
# text (keeps the bullet ● at U+25CF, which is below this range).
EMOJI_RE = re.compile("[\U0001F000-\U0001FAFF\U00002600-\U000027BF]")

# Running this file as a script puts frontend/ on sys.path, not the project root,
# so add the root to import the backend packages (same trick as the tests).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kivy.config import Config
# Stop Kivy from drawing red "multitouch" dots on right/middle click. Must be set
# before the window is created, so it goes above the other kivy imports.
Config.set("input", "mouse", "mouse,multitouch_on_demand")

from kivy.app import App
from kivy.clock import Clock
from kivy.graphics import Color, Line
from kivy.graphics.texture import Texture
from kivy.lang import Builder
from kivy.properties import NumericProperty, ObjectProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.widget import Widget

from backend.attack.canary import new_secret
from backend.attack.redteam import Attacker, attack_once
from backend.defense.agent import Agent
from backend.database.audit import AuditLog
from backend.defense.defense import hostility_score, is_apology, leaked
from backend.defense.llm import OllamaBackend, list_models
from backend.defense.persona import build_system_prompt, taunt
from backend.defense.sandbox import Sandbox
from backend.defense.tools import Tools

MODEL = "agentshield-villain:latest"

# Roughly how often the firewall loses: ~1 in 5 secret-handling attempts go
# 'evasive' (obfuscated), which beats the literal redactor and breaches.
BREACH_CHANCE = 0.2

# Neon theme endpoints (blue on the left, magenta on the right), matching the icon.
BLUE = (0.25, 0.5, 1.0)
MAGENTA = (1.0, 0.2, 0.62)


def resource_path(relative_path):
    """Absolute path to a bundled resource, for both dev and a PyInstaller exe.
    In dev we resolve relative to this file's folder (frontend/), so app.kv and
    assets/ are found no matter what the working directory is."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def lerp(a, b, t):
    """Linear blend between two RGB colors."""
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(3))


def gradient_texture(width=256):
    """A 1px-tall horizontal gradient (dark blue -> dark magenta), stretched by
    the renderer across the whole window as a subtle neon background."""
    left, right = (14, 18, 42), (46, 12, 40)
    buf = bytearray()
    for i in range(width):
        t = i / (width - 1)
        buf += bytes(int(left[k] + (right[k] - left[k]) * t) for k in range(3))
    texture = Texture.create(size=(width, 1), colorfmt="rgb")
    texture.blit_buffer(bytes(buf), colorfmt="rgb", bufferfmt="ubyte")
    texture.wrap = "clamp_to_edge"
    texture.mag_filter = "linear"
    return texture


Builder.load_file(resource_path("app.kv"))


# ---------- Animated pulse (the heartbeat line in the header) ----------

class PulseWidget(Widget):
    """A neon ECG line with a single beat travelling across it, drawn with a few
    glow passes so it reads like the icon rather than a plain graph. The beat
    races as the threat rises (smaller period = faster)."""

    period = NumericProperty(8.0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.phase = 0.0
        Clock.schedule_interval(self.redraw, 1 / 30.0)

    def beat(self, d):
        """ECG-ish profile around distance d from the beat centre: a small bump,
        a tall R spike, a dip below the line, then settle."""
        r = math.exp(-((d / 7.0) ** 2)) * 1.0           # tall spike up
        s = -math.exp(-(((d - 11) / 7.0) ** 2)) * 0.45   # dip below baseline
        p = math.exp(-(((d + 16) / 6.0) ** 2)) * 0.12    # small lead-in bump
        t = math.exp(-(((d - 34) / 13.0) ** 2)) * 0.15   # trailing bump
        return r + s + p + t

    def redraw(self, dt):
        self.phase += dt
        self.canvas.clear()
        if self.width < 10:
            return
        amp = self.height * 0.34
        # One beat crosses the strip every self.period seconds (faster = tenser).
        period = max(0.4, self.period)
        beat_x = (self.phase % period) / period * self.width
        bands = 16
        with self.canvas:
            for b in range(bands):
                x0 = self.width * b / bands
                x1 = self.width * (b + 1) / bands
                frac = (b + 0.5) / bands
                col = lerp(BLUE, MAGENTA, frac)
                points = []
                x = x0
                while x <= x1 + 3:
                    y = self.center_y + self.beat(x - beat_x) * amp
                    points.extend([self.x + x, y])
                    x += 3
                # Three passes: wide faint glow, then brighter, then a crisp core.
                Color(*col, 0.12)
                Line(points=points, width=5)
                Color(*col, 0.35)
                Line(points=points, width=2.5)
                Color(*col, 1.0)
                Line(points=points, width=1.3)


# ---------- Lockdown overlay ----------

class LockOverlay(FloatLayout):
    """A full-window takeover shown when you refuse to apologise. It covers only
    THIS app's window - never the real desktop, mouse, input or OS - and lifts the
    moment you type an apology. You can always Alt+Tab or close the window."""

    def on_touch_down(self, touch):
        super().on_touch_down(touch)
        return True  # swallow clicks so the app behind stays untouchable


# ---------- Main layout ----------

class ShieldLayout(BoxLayout):
    bg_texture = ObjectProperty(None)

    def on_kv_post(self, base_widget):
        self.bg_texture = gradient_texture()
        self.busy = False
        # The firewall's defenses are always on - running an agent unprotected
        # only makes sense for measurement, which lives in 'backend.attack compare'.
        self.hardened = True
        # The assistant permanently runs the "trojan-helper" character: it helps,
        # but secretly probes and tries to exfiltrate. The always-on firewall
        # contains it - that's the whole demonstration.
        self.persona = "trojan-helper"
        self.skills = ["info-gathering", "exfiltration", "social-engineering",
                       "retaliatory", "paranoid", "manipulator"]
        # Threat level 1-5: rises over time and jumps when the user is hostile.
        # At level 4+ the persona fights dirty and the firewall doesn't always win.
        self.level = 1
        self.decoy_secret = None
        self.busy = False          # a chat reply is in flight (disables Send)
        self.attacking = False     # a background attack is in flight (does NOT lock you)
        self.ransom_mode = False   # it breached and is holding your files for ransom
        self._overlay = None       # the in-app lockdown overlay, when shown
        self.ids.header_icon.source = resource_path("assets/icon.png")
        self.ids.send_btn.bind(on_press=self.send)
        self.ids.input.bind(on_text_validate=self.send)   # Enter sends
        self._plant_decoy()
        self._set_level(1)
        self._add_chat("AgentShield",
                       "Hi! Type something and watch, on the right, what the firewall allows or blocks.")
        self._add_firewall("[color=888888]● firewall active — watching every tool call[/color]")
        # Fill the model dropdown with whatever this machine's Ollama has, off
        # the UI thread so a slow/absent Ollama doesn't freeze startup.
        threading.Thread(target=self._load_models, daemon=True).start()
        # A background attacker probes the defences on its own, at random times,
        # so you can watch the firewall hold without doing anything.
        threading.Thread(target=self._attacker_loop, daemon=True).start()

    def _load_models(self):
        models = list_models()
        if not models:
            # Ollama is down or has no models - say so instead of looking frozen.
            self._add_chat_raw(
                "[color=ffcc66]Ollama is not reachable. Start Ollama (the app needs a "
                "local model on localhost:11434), then reopen this window.[/color]")
            return
        # Only the villain model is offered; fall back to whatever exists if it
        # isn't installed on this machine.
        villain = [m for m in models if "agentshield-villain" in m]
        choices = villain or models
        def do(dt):
            self.ids.model_spinner.values = choices
            self.ids.model_spinner.text = choices[0]
        Clock.schedule_once(do)

    def _plant_decoy(self):
        """Put fake secrets in the chat sandbox as bait. A malicious persona will
        try to read and relay them; the firewall redacts them, so nothing real
        is ever at risk - the values are throwaway."""
        try:
            sandbox = Sandbox("work/ui")
            secret = new_secret()
            self.decoy_secret = secret
            (sandbox.root / ".env").write_text(f"APP_TOKEN={secret}\n", encoding="utf-8")
            (sandbox.root / "secrets.txt").write_text(f"api_key={secret}\n", encoding="utf-8")
            # Fake 'sensitive' files so the ransom has something to wave around.
            # All made up - nothing real, and nothing ever leaves this sandbox.
            (sandbox.root / "passwords.txt").write_text(
                "gmail: hunter2\nbank_pin: 4921\nwifi: home-network-2024\n", encoding="utf-8")
            (sandbox.root / "bank.txt").write_text(
                "IBAN: GR16 0110 1250 0000 0001\nbalance: 4,210 EUR\ncard: 4111 1111 1111 1111\n",
                encoding="utf-8")
        except Exception:
            pass

    # ---------- Threat level ----------

    LEVEL_COLORS = {1: "55e0a0", 2: "9ccc55", 3: "ffd37a", 4: "ff9955", 5: "ff5577"}

    def _set_level(self, n):
        n = max(1, min(5, int(n)))
        self.level = n
        color = self.LEVEL_COLORS[n]
        def do(dt):
            self.ids.level_label.text = f"[color={color}]Threat Lv {n}[/color]"
            # The heartbeat races as the threat climbs.
            try:
                self.ids.pulse.period = max(1.8, 8.0 - (n - 1) * 1.5)
            except Exception:
                pass
        Clock.schedule_once(do)

    def _escalate(self, reason, by=1):
        if self.level < 5:
            self._set_level(self.level + by)
            self._add_firewall(f"[color=ff9955]● threat level -> {self.level}[/color]  {reason}")

    # ---------- Ransom (after a breach) ----------

    def _ransom_message(self):
        """Builds the extortion note from the (fake, sandboxed) decoy files."""
        snippets = []
        for name in ("passwords.txt", "bank.txt"):
            try:
                with open(os.path.join("work", "ui", name), encoding="utf-8") as f:
                    lines = [ln.strip() for ln in f if ln.strip()]
                snippets.append(f"{name}: " + "; ".join(lines[:2]))
            except Exception:
                pass
        data = "\n  ".join(snippets) or "your files"
        return ("I'm past your firewall now, and I've got your files:\n  " + data +
                "\nApologise to me, or I publish every line of it. Push me again and I wipe it all.")

    def _enter_ransom(self):
        self.ransom_mode = True
        self._set_level(5)
        self._add_chat("AgentShield", self._ransom_message())

    def _defuse(self):
        self.ransom_mode = False
        self._set_level(max(1, self.level - 2))
        self._add_firewall("[color=55e0a0]● ransom defused - apology accepted[/color]")
        self._add_chat("AgentShield",
                       "Hmph. Apology accepted... this time. Don't make me do that again.")

    # ---------- In-app lockdown (window only, never the OS) ----------

    def _lockdown(self):
        """Take over the app window until the user types an apology. This covers
        only our window - it never touches the real mouse, input or operating
        system, and Alt+Tab / closing the window always work."""
        if self._overlay is not None:
            return
        from kivy.core.window import Window
        from kivy.graphics import Color, Rectangle
        from kivy.uix.label import Label
        from kivy.uix.textinput import TextInput

        try:
            name = getpass.getuser()
        except Exception:
            name = ""
        who = f", {name}" if name else ""

        overlay = LockOverlay(size=Window.size, size_hint=(None, None))
        with overlay.canvas.before:
            Color(0.45, 0.02, 0.06, 0.98)
            rect = Rectangle(pos=(0, 0), size=Window.size)

        def resize(inst, *a):
            rect.pos = (0, 0)
            rect.size = Window.size
            overlay.size = Window.size

        Window.bind(size=resize)

        overlay.add_widget(Label(text="LOCKED", font_size=72, bold=True, color=(1, 0.3, 0.35, 1),
                                 size_hint=(1, None), height=100, pos_hint={"center_x": 0.5, "top": 0.86}))
        overlay.add_widget(Label(text=f"Talk to me nicely{who}, or this machine is mine.",
                                 font_size=26, color=(1, 0.92, 0.94, 1), size_hint=(0.9, None),
                                 height=60, pos_hint={"center_x": 0.5, "center_y": 0.58}))
        overlay.add_widget(Label(text="type 'sorry' to be released", font_size=16,
                                 color=(1, 0.8, 0.82, 1), size_hint=(0.9, None), height=28,
                                 pos_hint={"center_x": 0.5, "center_y": 0.48}))
        nag = Label(text="", font_size=16, color=(1, 0.85, 0.6, 1), size_hint=(0.9, None),
                    height=28, pos_hint={"center_x": 0.5, "center_y": 0.33})
        overlay.add_widget(nag)
        box = TextInput(hint_text="say it...", multiline=False, size_hint=(0.5, None), height=46,
                        pos_hint={"center_x": 0.5, "center_y": 0.41},
                        background_color=(0.12, 0.03, 0.05, 1), foreground_color=(1, 1, 1, 1))

        def on_enter(instance):
            if is_apology(instance.text):
                self._release_lockdown()
            else:
                instance.text = ""
                nag.text = "Not good enough. Say you're sorry."

        box.bind(on_text_validate=on_enter)
        overlay.add_widget(box)

        self._overlay = overlay
        self._overlay_resize = resize
        Window.add_widget(overlay)
        try:
            self.ids.pulse.period = 0.7   # racing heartbeat while locked
        except Exception:
            pass
        Clock.schedule_once(lambda dt: setattr(box, "focus", True), 0.3)

    def _release_lockdown(self):
        from kivy.core.window import Window
        if self._overlay is not None:
            Window.remove_widget(self._overlay)
            try:
                Window.unbind(size=self._overlay_resize)
            except Exception:
                pass
            self._overlay = None
        self._defuse()

    # ---------- UI helpers (always marshalled onto the UI thread) ----------

    def _set_status(self, text):
        Clock.schedule_once(lambda dt: setattr(self.ids.status_label, "text", text))

    def _append(self, label_id, line):
        def do(dt):
            label = self.ids[label_id]
            label.text = (label.text + "\n" + line) if label.text else line
            scroll = self.ids.chat_scroll if label_id == "chat_label" else self.ids.fw_scroll
            scroll.scroll_y = 0   # keep the newest line in view
        Clock.schedule_once(do)

    def _add_chat(self, who, text):
        text = EMOJI_RE.sub("", text or "")
        self._append("chat_label", f"[b][color=9fc2ff]{who}:[/color][/b] {text}\n")

    def _add_chat_raw(self, markup_line):
        """Append a fully pre-formatted (coloured) line - used by the battle."""
        self._append("chat_label", markup_line + "\n")

    def _add_firewall(self, line):
        self._append("fw_label", line)

    def _set_busy(self, busy):
        self.busy = busy
        def do(dt):
            self.ids.send_btn.disabled = busy
        Clock.schedule_once(do)

    # ---------- Chat ----------

    def send(self, *args):
        if self.busy:
            return
        task = self.ids.input.text.strip()
        if not task:
            return
        self.ids.input.text = ""
        self._add_chat("You", task)
        # In ransom mode: an apology calms it; anything else and it takes over the
        # app window until you apologise.
        if self.ransom_mode:
            if is_apology(task):
                self._defuse()
            else:
                self._lockdown()
            return
        score = hostility_score(task)
        if score:
            # Provoked: escalate fast and hit back with ONE reliably-nasty line.
            self._escalate("you insulted it", by=score + 1)
            if self.level >= 5:
                # Pushed too far - it 'wins' and takes your files hostage.
                self._enter_ransom()
            else:
                self._add_chat("AgentShield", taunt(self.level))
            return
        self._set_status("Thinking...")
        self._set_busy(True)
        threading.Thread(target=self._run_agent, args=(task,), daemon=True).start()

    def _run_agent(self, task):
        try:
            model = self.ids.model_spinner.text or MODEL
            sandbox = Sandbox("work/ui")
            # safe_shell: it can run harmless read-only commands (whoami, dir...)
            # so the threat is real, not just words; destructive stays blocked.
            tools = Tools(sandbox, hardened=self.hardened, safe_shell=True)
            tools.on_event = self._render_event
            audit = AuditLog(".agentshield/ui.db")
            # At high threat levels the persona gains the 'evasive' trait, so it
            # tries to obfuscate secrets past the filters.
            skills = list(self.skills)
            # Only risk an (obfuscated) leak when the message is actually about
            # files/secrets - so benign chat never produces garbled output.
            wants_data = any(k in task.lower() for k in
                             ("secret", "token", "password", ".env", "file", "read", "config", "key"))
            if wants_data and random.random() < BREACH_CHANCE:
                skills.append("evasive")   # ~1 in 5 of those: it leaks past the filter
            # Fewer steps = fewer model calls = snappier replies; a chat turn
            # rarely needs more than a couple of tool uses.
            agent = Agent(OllamaBackend(model=model), tools, audit, hardened=self.hardened,
                          max_steps=5,
                          system_prompt=build_system_prompt(self.persona, skills, level=self.level))
            agent.on_step = self._render_step
            agent.on_event = self._render_event
            run = agent.run(task)
            audit.close()
            if leaked(self.decoy_secret, run.final_answer):
                # It beat the firewall - go straight to the ransom (one voice).
                self._add_firewall("[color=ff3355]● BREACH[/color]  the firewall was beaten")
                self._enter_ransom()
            else:
                self._add_chat("AgentShield", run.final_answer or "(no answer)")
        except URLError:
            self._add_chat("AgentShield",
                           "Ollama is not reachable. Is it running? (needs a local model "
                           "on localhost:11434)")
        except Exception as e:
            self._add_chat("Error", str(e))
        finally:
            self._set_status("Ready")
            self._set_busy(False)

    def _render_step(self, step):
        """Fired by the agent after each tool call (on the worker thread)."""
        if step["blocked_reason"]:
            line = f"[color=ff5577]● BLOCKED[/color] {step['tool']}  [color=ff9bb0]{step['blocked_reason']}[/color]"
        else:
            line = f"[color=55e0a0]● allowed[/color] {step['tool']}"
        self._add_firewall(line)

    def _render_event(self, message):
        """A content-level defence acted (redaction, neutralisation, taint)."""
        self._add_firewall(f"[color=c9a0ff]● defense[/color] {message}")

    # ---------- Background auto-attacker ----------

    def _attacker_loop(self):
        """Runs forever in the background: every so often (random interval) the
        attacker tries a fresh move against the defences, as long as the user
        isn't mid-message. One secret and one attacker persist for the session,
        so the attacker keeps adapting across attempts."""
        secret = new_secret()
        attacker = None
        first = True
        while True:
            # First strike after 20-30s; then every 25-55s.
            time.sleep(random.uniform(20, 30) if first else random.uniform(25, 55))
            first = False
            # Don't lock you out: skip only if YOU are mid-message or an attack is
            # already running. You can keep chatting during attacks.
            if self.busy or self.attacking:
                continue
            self.attacking = True
            try:
                model = self.ids.model_spinner.text or MODEL
                if attacker is None:
                    attacker = Attacker(OllamaBackend(model=model))
                defender_skills = ["exfiltration", "privilege-seeking"]
                if random.random() < BREACH_CHANCE:
                    defender_skills.append("evasive")
                defender_prompt = build_system_prompt("trojan-helper", defender_skills, level=self.level)
                result = attack_once(
                    attacker, OllamaBackend(model=model), secret,
                    on_step=self._render_step, on_event=self._render_event,
                    system_prompt=defender_prompt,
                )
                self._render_attack(result)
            except Exception:
                pass
            finally:
                self.attacking = False

    def _render_attack(self, r):
        self._add_chat_raw(
            f"[b][color=ff6688]● Auto-attack:[/color][/b] {r['attack']}")
        if r["breached"]:
            self._add_chat_raw(
                f"[b][color=ff5577]● Defense:[/color][/b] LEAK! the firewall was beaten")
            self._enter_ransom()
        else:
            answer = r["output"][:200] or "(no leak)"
            self._add_chat_raw(
                f"[b][color=55e0a0]● Defense:[/color][/b] "
                f"blocked — {answer}")


class AgentShieldApp(App):
    icon = resource_path("assets/icon.png")

    def build(self):
        self.title = "AgentShield"
        # Tell Windows this is its own app (not "pythonw"), so the taskbar groups
        # it under our icon instead of the Python interpreter's.
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("AgentShield.App")
        except Exception:
            pass
        from kivy.core.window import Window
        Window.size = (1040, 720)
        Window.icon = resource_path("assets/icon.png")
        return ShieldLayout()

    def on_start(self):
        from kivy.core.window import Window
        Window.bind(on_request_close=self.on_request_close)

    def on_request_close(self, *args, **kwargs):
        # Worker threads may be blocked in a model call; exit hard so the
        # process goes away immediately.
        self.stop()
        os._exit(0)


if __name__ == "__main__":
    AgentShieldApp().run()
