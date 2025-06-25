# LemonHaze - 2025
import sys
import os

from .config import *
from .tracking import *

import re
import hashlib
from html import escape

import ida_pro
import ida_kernwin
import idaapi
import idautils
import idc
import ida_name
import ida_hexrays

ACTION_EXPORT_WEB = "lemonutils:export_web"

# Settings
MAX_BASENAME_LEN = 80


def sanitize_name(name, fva):
    safe = re.sub(r'[^a-zA-Z0-9_\-]', '_', name)
    if len(safe) > MAX_BASENAME_LEN:
        h = hashlib.sha1(name.encode()).hexdigest()[:8]
        safe = f"{safe[:60]}_{h}"
    return f"{safe}_{fva:X}"

def export_function(fva):
    name = idc.get_func_name(fva)
    sname = sanitize_name(name, fva)
    dis_file = os.path.join(FUNC_DIR, f"{sname}.asm.txt")
    c_file = os.path.join(FUNC_DIR, f"{sname}.c.txt")

    try:
        lines = []
        for head in idautils.Heads(fva, idc.find_func_end(fva)):
            dis_line = idc.generate_disasm_line(head, 0) or ""
            lines.append(f"{head:08X}: {dis_line}")
        with open(dis_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    except Exception as e:
        print(f"[!] Failed to write disasm for {name}: {e}")

    try:
        decomp = idaapi.decompile(fva)
        with open(c_file, "w", encoding="utf-8") as f:
            f.write(str(decomp) if decomp else "// No decompilation available")
    except Exception as e:
        print(f"[!] Failed to decompile {name}: {e}")
        with open(c_file, "w", encoding="utf-8") as f:
            f.write(f"// Decompilation failed for {name}\n")

    return name, sname, fva


def export_to_web():
    # Init first
    proj_name = re.sub(r'[^a-zA-Z0-9]', '_', idc.get_root_filename())
    OUTPUT_DIR = os.path.join(idaapi.get_user_idadir(), proj_name)
    FUNC_DIR = os.path.join(OUTPUT_DIR, "functions")
    os.makedirs(FUNC_DIR, exist_ok=True)

    # Clear dirty pseudocode output and export
    ida_hexrays.clear_cached_cfuncs()
    
    function_entries = []
    for fva in idautils.Functions():
        try:
            raw_name = idc.get_func_name(fva)
            demangled = ida_name.demangle_name(raw_name, idc.get_inf_attr(idc.INF_SHORT_DN))
            final_name = demangled if demangled else raw_name
            name, sname, fva = export_function(fva)
            function_entries.append((final_name, sname, fva))
        except Exception as e:
            print(f"[!] Error processing function @ {fva:X}: {e}")
    
    function_data_js = "const functions = [\n"
    for name, sname, fva in function_entries:
        escaped = name.replace("\\", "\\\\").replace("'", "\\'")
        function_data_js += f"  ['{escaped}', '{sname}', '{fva:X}'],\n"
    function_data_js += "];"
    
    # Generate
    html_path = os.path.join(OUTPUT_DIR, "index.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write("""<!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>IDA Exported Functions</title>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/base16/dracula.min.css">
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/cpp.min.js"></script>
      <style>
        :root {
          --bg: #f0f0f0;
          --fg: #000;
          --border: #ccc;
          --panel-bg: #fafafa;
        }
        .dark {
          --bg: #1e1e1e;
          --fg: #ddd;
          --border: #444;
          --panel-bg: #2b2b2b;
        }
        body {
          margin: 0;
          font-family: sans-serif;
          display: flex;
          height: 100vh;
          background: var(--bg);
          color: var(--fg);
        }
        #sidebar {
          width: 300px;
          min-width: 150px;
          background: var(--panel-bg);
          border-right: 1px solid var(--border);
          padding: 1em;
          overflow-y: auto;
          resize: horizontal;
          overflow: auto;
        }
        #toggle-dark {
          margin-bottom: 1em;
        }
        #content {
          flex-grow: 1;
          display: flex;
          overflow: hidden;
          position: relative;
        }
        #disasm, #pseudocode {
          flex: 1;
          padding: 1em;
          overflow-y: auto;
          white-space: pre-wrap;
          font-family: monospace;
          background: var(--panel-bg);
        }
        #pseudocode code.hljs {
          display: block;
          white-space: pre-wrap;
        }
        .func-entry {
          margin-bottom: 1em;
        }
        .func-entry button {
          margin-top: 0.25em;
          padding: 0.25em 0.5em;
          font-size: 0.9em;
        }
        h1 {
          font-size: 1.3em;
        }
        .meta {
          font-size: 0.85em;
          color: var(--fg);
          opacity: 0.6;
        }
        .gutter {
          width: 5px;
          background: var(--border);
          cursor: ew-resize;
        }
      </style>
    </head>
    <body>
    <div id="sidebar">
      <button id="toggle-dark">Toggle Dark Mode</button>
      <h1>IDA Exported Functions</h1>
    """)
        for demangled, sname, fva in function_entries:
            f.write(f'<div class="func-entry"><b>{escape(demangled)}</b><br>'
                    f'<span class="meta">@ {fva:X}</span><br>'
                    f'<button onclick="viewFunction(\'{escape(sname)}\')">View</button></div>\n')
    
        f.write("""</div>
    <div id="content">
      <div id="disasm"><pre><code class="language-asm6502">...</code></pre></div>
      <div class="gutter" id="splitter"></div>
      <div id="pseudocode"><pre><code class="language-cpp">/* ... */</code></pre></div>
    </div>
    <script>
    """ + function_data_js + """
    
    function viewFunction(base) {
      fetch('functions/' + base + '.asm.txt')
        .then(res => res.text())
        .then(txt => document.getElementById('disasm').textContent = txt)
        .catch(() => document.getElementById('disasm').textContent = '[Error loading disassembly]');
    
      fetch('functions/' + base + '.c.txt')
        .then(res => res.text())
        .then(txt => {
          const codeElem = document.querySelector('#pseudocode code');
          codeElem.textContent = txt;
          hljs.highlightElement(codeElem);
        })
        .catch(() => {
          document.querySelector('#pseudocode code').textContent = '[Error loading pseudocode]';
        });
    }
    
    // === Dark Mode Toggle ===
    const toggle = document.getElementById('toggle-dark');
    const body = document.body;
    if (localStorage.getItem('dark') === '1') body.classList.add('dark');
    toggle.onclick = () => {
      body.classList.toggle('dark');
      localStorage.setItem('dark', body.classList.contains('dark') ? '1' : '0');
    };
    
    // === Splitter Drag Logic ===
    const splitter = document.getElementById('splitter');
    const left = document.getElementById('disasm');
    const right = document.getElementById('pseudocode');
    
    let isDragging = false;
    splitter.addEventListener('mousedown', e => {
      isDragging = true;
      document.body.style.cursor = 'ew-resize';
    });
    window.addEventListener('mousemove', e => {
      if (!isDragging) return;
      const percent = e.clientX / window.innerWidth;
      left.style.flex = percent;
      right.style.flex = 1 - percent;
    });
    window.addEventListener('mouseup', () => {
      isDragging = false;
      document.body.style.cursor = '';
    });
    </script>
    </body>
    </html>""")
    
    print(f"\n[+] Export complete. Written to {html_path}")
    
class ExportWebHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        export_to_web()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def register_export_web():
    idaapi.register_action(
        idaapi.action_desc_t(
            ACTION_EXPORT_WEB,
            "Export to Web",
            ExportWebHandler(),
            None
        )
    )
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/Export/",
        ACTION_EXPORT_WEB,
        ida_kernwin.SETMENU_APP
    )


def unregister_export_web():
    ida_kernwin.unregister_action(ACTION_EXPORT_WEB)
    
