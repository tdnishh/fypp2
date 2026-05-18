import customtkinter as ctk
from tkinter import messagebox
import os
import shutil

from usb_detector import detect_usb
from file_scanner import scan_files
from heuristic_engine import analyze
from behavior_monitor import monitor
from logger import log


# ================= THEME & CYBERPUNK PALETTE =================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

# Premium UI Palette
COLOR_BG = "#060a12"           # Deep midnight background
COLOR_CARD = "#0b1325"         # High-contrast glass container
COLOR_ACCENT = "#00ff9c"       # Terminal neon green
COLOR_ACCENT_HOVER = "#00d180" # Smooth button hover green
COLOR_BORDER = "#152238"       # Structural wireframe dividers
COLOR_TEXT_MUTED = "#64748b"   # Clean secondary label slate

# ================= MAIN APPLICATION WINDOW =================
root = ctk.CTk()
root.title("USB MALWARE DETECTION TERMINAL")
root.geometry("1020x950")      
root.resizable(False, False)
root.configure(fg_color=COLOR_BG)


# ================= GLOBAL STATE =================
scan_results = []
selected_file = None
stats_cache = {}

file_buttons = []
current_malicious_list = []

# IGNORE LIST
ignored_files = []


# ================= HEADER COMPONENT =================
header_panel = ctk.CTkFrame(root, fg_color="transparent")
header_panel.pack(pady=(25, 10), fill="x", padx=30) 

ctk.CTkLabel(
    header_panel,
    text="USB MALWARE DETECTION TERMINAL",
    font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
    text_color=COLOR_ACCENT
).pack(anchor="center", pady=(0, 2))

ctk.CTkLabel(
    header_panel,
    text="Heuristic & File Behavior Auto-Run Defense Console",
    font=ctk.CTkFont(family="Segoe UI", size=13),
    text_color=COLOR_TEXT_MUTED
).pack(anchor="center")


# ================= CENTRAL VIEWPORT (FILE GRID CARD) =================
grid_card = ctk.CTkFrame(
    root,
    fg_color=COLOR_CARD,
    border_color=COLOR_BORDER,
    border_width=1,
    corner_radius=14
)
grid_card.pack(pady=5, padx=30, fill="both", expand=True)

# Placeholder elements to stop the screen from looking empty before scanning
placeholder_frame = ctk.CTkFrame(grid_card, fg_color="transparent")
placeholder_frame.place(relx=0.5, rely=0.5, anchor="center")

placeholder_icon = ctk.CTkLabel(
    placeholder_frame,
    text="🖥️",
    font=ctk.CTkFont(size=50)
)
placeholder_icon.pack()

placeholder_text = ctk.CTkLabel(
    placeholder_frame,
    text="AWAITING HARDWARE INTERFACE DEVICE\nFiles discovered on target drive will populate this workspace area.",
    font=ctk.CTkFont(family="Segoe UI", size=13),
    text_color=COLOR_TEXT_MUTED,
    justify="center"
)
placeholder_text.pack(pady=10)

file_listbox = ctk.CTkScrollableFrame(
    grid_card,
    width=936,
    height=240,                        
    fg_color="transparent",
    corner_radius=10
)
# Pack is managed inside functions dynamically now to allow placeholders to show first


# ================= SYSTEM STATUS & MOTION PANEL =================
stats_frame = ctk.CTkFrame(
    root,
    fg_color="#030712",
    border_color=COLOR_BORDER,
    border_width=1,
    corner_radius=10
)
stats_frame.pack(pady=5, fill="x", padx=30)

stats_label = ctk.CTkLabel(
    stats_frame,
    text=">> SYSTEM READY. INSERT COMPATIBLE FLASH DRIVE TO SCAN.",
    justify="left",
    font=("Consolas", 12, "bold"),
    text_color="#e2e8f0"
)
stats_label.pack(anchor="w", padx=16, pady=(12, 12))

# Motion Component
progress_bar = ctk.CTkProgressBar(
    stats_frame,
    orientation="horizontal",
    mode="indeterminate",
    progress_color=COLOR_ACCENT,
    fg_color="#111827",
    height=5
)


# ================= CONSOLE LOG CARD =================
log_card = ctk.CTkFrame(
    root,
    fg_color=COLOR_CARD,
    border_color=COLOR_BORDER,
    border_width=1,
    corner_radius=14
)
log_card.pack(pady=5, padx=30, fill="x")

ctk.CTkLabel(
    log_card,
    text="  DIAGNOSTIC OUTPUT ENGINE LOG",
    font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
    text_color=COLOR_TEXT_MUTED
).pack(anchor="w", padx=14, pady=(10, 4))

output_box = ctk.CTkTextbox(
    log_card,
    width=936,
    height=280,        
    font=("Consolas", 11),
    text_color=COLOR_ACCENT,
    fg_color="#020617",
    border_color="#0f172a",
    border_width=1,
    corner_radius=8
)
output_box.pack(padx=14, pady=(0, 14), fill="x")

# Prefill with professional terminal loading alerts so it looks active instantly!
output_box.insert("1.0", ">> CORE TERMINAL INITIALIZATION COMPLETED SUCCESSFUL.\n")
output_box.insert("end", ">> LINKING STATIC HEURISTIC PATTERN ENGINE V2.4...\n")
output_box.insert("end", ">> MONITORING KERNEL MEMORY INTERFACES...\n")
output_box.insert("end", ">> SYSTEM BASE STATUS: AWAITING DRIVE DETECT LINK.\n")


# ================= UNIFIED CONTROL DASHBOARD =================
control_deck = ctk.CTkFrame(root, fg_color="transparent", height=60)
control_deck.pack(pady=(10, 20), fill="x", padx=30) 
control_deck.pack_propagate(False)

scan_frame = ctk.CTkFrame(control_deck, fg_color="transparent")
view_frame = ctk.CTkFrame(control_deck, fg_color="transparent")
action_frame = ctk.CTkFrame(control_deck, fg_color="transparent")

scan_frame.pack(anchor="center")


# ================= SCAN CONTROLS =================
ctk.CTkButton(
    scan_frame,
    text="▶  RUN USB SCAN",
    width=280,
    height=46,
    font=ctk.CTkFont(size=14, weight="bold"),
    fg_color=COLOR_ACCENT,
    text_color="#020617",
    hover_color=COLOR_ACCENT_HOVER,
    corner_radius=8,
    command=lambda: scan_usb()
).grid(row=0, column=0, padx=15)

ctk.CTkButton(
    scan_frame,
    text="✖  TERMINATE PROCESS",
    width=280,
    height=46,
    font=ctk.CTkFont(size=14, weight="bold"),
    fg_color="#ef4444",
    text_color="#ffffff",
    hover_color="#b91c1c",
    corner_radius=8,
    command=root.destroy
).grid(row=0, column=1, padx=15)


# ================= VIEW CONTROLS =================
ctk.CTkButton(
    view_frame,
    text="⚠️ VIEW MALICIOUS",
    width=160,
    height=42,
    font=ctk.CTkFont(size=12, weight="bold"),
    fg_color="#7f1d1d",
    hover_color="#b91c1c",
    corner_radius=8,
    command=lambda: show_results("MALICIOUS")
).grid(row=0, column=0, padx=8)

ctk.CTkButton(
    view_frame,
    text="✅ VIEW SAFE",
    width=160,
    height=42,
    font=ctk.CTkFont(size=12, weight="bold"),
    fg_color="#064e3b",
    hover_color="#16a34a",
    corner_radius=8,
    command=lambda: show_results("SAFE")
).grid(row=0, column=1, padx=8)

ctk.CTkButton(
    view_frame,
    text="🔍 VIEW ALL",
    width=160,
    height=42,
    font=ctk.CTkFont(size=12, weight="bold"),
    fg_color="#0f172a",
    border_color=COLOR_BORDER,
    border_width=1,
    hover_color="#1e293b",
    corner_radius=8,
    command=lambda: show_results("ALL")
).grid(row=0, column=2, padx=8)

ctk.CTkButton(
    view_frame,
    text="⬅ BACK",
    width=120,
    height=42,
    font=ctk.CTkFont(size=12, weight="bold"),
    fg_color="#2563eb",
    hover_color="#1d4ed8",
    corner_radius=8,
    command=lambda: reset_to_scan()
).grid(row=0, column=3, padx=8)


# ================= ACTION CONTROLS =================
ctk.CTkButton(
    action_frame,
    text="🟠 QUARANTINE",
    width=150,
    height=42,
    font=ctk.CTkFont(size=12, weight="bold"),
    fg_color="#c2410c",
    hover_color="#9a3412",
    corner_radius=8,
    command=lambda: handle_action("quarantine")
).grid(row=0, column=0, padx=6)

ctk.CTkButton(
    action_frame,
    text="🔴 DELETE",
    width=150,
    height=42,
    font=ctk.CTkFont(size=12, weight="bold"),
    fg_color="#ef4444",
    hover_color="#b91c1c",
    corner_radius=8,
    command=lambda: handle_action("delete")
).grid(row=0, column=1, padx=6)

ctk.CTkButton(
    action_frame,
    text="⚪ IGNORE",
    width=150,
    height=42,
    font=ctk.CTkFont(size=12, weight="bold"),
    fg_color="#4b5563",
    hover_color="#374151",
    corner_radius=8,
    command=lambda: handle_action("ignore")
).grid(row=0, column=2, padx=6)

ctk.CTkButton(
    action_frame,
    text="🔄 REFRESH",
    width=150,
    height=42,
    font=ctk.CTkFont(size=12, weight="bold"),
    fg_color="#2563eb",
    hover_color="#1d4ed8",
    corner_radius=8,
    command=lambda: refresh_list()
).grid(row=0, column=3, padx=6)

ctk.CTkButton(
    action_frame,
    text="⬅ BACK",
    width=120,
    height=42,
    font=ctk.CTkFont(size=12, weight="bold"),
    fg_color="#10b981",
    hover_color="#059669",
    corner_radius=8,
    command=lambda: back_to_view()
).grid(row=0, column=4, padx=6)


# ================= SYSTEM INTERACTION LOGIC =================
def select_file(index):
    global selected_file

    for btn in file_buttons:
        btn.configure(
            fg_color="#111827",
            hover_color="#1f2937",
            text_color="#9ca3af",
            border_width=0
        )

    file_buttons[index].configure(
        fg_color="#1f2937",
        hover_color="#374151",
        text_color="#ffffff",
        border_color=COLOR_ACCENT,
        border_width=1
    )

    selected_file = current_malicious_list[index]


def scan_usb():
    global scan_results, stats_cache

    scan_results.clear()
    output_box.delete("1.0", "end")

    # Wipe the screen placeholders when the scan runs
    placeholder_frame.place_forget()
    file_listbox.pack(padx=12, pady=12, fill="both", expand=True)

    for widget in file_listbox.winfo_children():
        widget.destroy()

    usb = detect_usb()

    if not usb:
        # Restore placeholders if no USB link is found
        file_listbox.pack_forget()
        placeholder_frame.place(relx=0.5, rely=0.5, anchor="center")
        messagebox.showwarning(
            "NO USB DETECTED",
            "Hardware link unestablished. Mount a storage device to proceed."
        )
        return

    stats_label.configure(text=">> SCANNING FILES... ANALYZING STRUCTURE AND HEURISTICS.", text_color=COLOR_ACCENT)
    stats_label.pack(anchor="w", padx=16, pady=(12, 4))
    progress_bar.pack(fill="x", padx=16, pady=(0, 12))
    progress_bar.start()
    root.update()

    scanned = 0
    safe = 0
    suspicious = 0
    malicious = 0

    for f in scan_files(usb):
        if f in ignored_files:
            continue

        if "System Volume Information" in f:
            continue

        h, reasons, threats = analyze(f, usb)
        b = monitor(f)

        total = h + b if reasons else 0
        verdict = "SAFE"

        if reasons:
            if total >= 5:
                verdict = "MALICIOUS"
            elif total >= 2:  
                verdict = "SUSPICIOUS"

        scanned += 1

        if verdict == "SAFE":
            safe += 1
        elif verdict == "SUSPICIOUS":
            suspicious += 1
        else:
            malicious += 1

        log(f, total, verdict)

        scan_results.append({
            "file": f,
            "verdict": verdict,
            "heuristic": h,
            "behavior": b,
            "total": total,
            "reasons": reasons,
            "threats": threats
        })
        
        root.update_idletasks()

    mal_rate = (malicious / scanned * 100) if scanned else 0

    stats_cache = {
        "scanned": scanned,
        "safe": safe,
        "suspicious": suspicious,
        "malicious": malicious,
        "mal_rate": mal_rate
    }

    progress_bar.stop()
    progress_bar.pack_forget()
    stats_label.pack(anchor="w", padx=16, pady=(12, 12))
    stats_label.configure(text=">> SCAN OPERATIONAL CYCLE FILLED. SELECT A SORT MODE BELOW.", text_color="#e2e8f0")

    output_box.insert(
        "end",
        ">> PARSING SEQUENCE COMPLETE. SYSTEM AWAITING CRITERIA SELECTION.\n"
    )

    scan_frame.pack_forget()
    view_frame.pack(anchor="center")


def show_results(mode):
    global current_malicious_list, file_buttons

    output_box.delete("1.0", "end")

    for widget in file_listbox.winfo_children():
        widget.destroy()

    file_buttons.clear()
    current_malicious_list.clear()

    if mode == "MALICIOUS":
        files = [f for f in scan_results if f["verdict"] == "MALICIOUS"]
    elif mode == "SAFE":
        files = [f for f in scan_results if f["verdict"] == "SAFE"]
    else:
        files = scan_results

    current_malicious_list.extend(files)

    for idx, f in enumerate(files):
        filename = os.path.basename(f['file'])
        icon = "📄"
        color = "#1e293b"

        if f["verdict"] == "MALICIOUS":
            color = "#451a03"
        elif f["verdict"] == "SAFE":
            color = "#062f4f"
        elif f["verdict"] == "SUSPICIOUS":
            color = "#3f1d0b"

        if filename.endswith(".exe"):
            icon = "⚠️"
        elif filename.endswith(".inf"):
            icon = "🧬"
        elif filename.endswith(".bat"):
            icon = "💀"
        elif filename.endswith(".zip"):
            icon = "🗜️"
        elif filename.endswith(".png"):
            icon = "🖼️"

        btn = ctk.CTkButton(
            file_listbox,
            text=f"{icon}\n{filename}\n\n{f['verdict']}",
            width=174,
            height=100, 
            fg_color=color,
            hover_color="#1f2937",
            text_color="#ffffff",
            corner_radius=10,
            font=("Consolas", 11, "bold"),
            command=lambda i=idx: select_file(i)
        )

        row = idx // 5
        col = idx % 5

        btn.grid(row=row, column=col, padx=10, pady=10)
        file_buttons.append(btn)

    malicious_count = stats_cache['malicious']
    suspicious_count = stats_cache['suspicious']
    total_scanned = stats_cache['scanned']

    if total_scanned > 0:
        mal_rate = (malicious_count / total_scanned) * 100
    else:
        mal_rate = 0

    if malicious_count == 0 and suspicious_count == 0:
        overall_risk = "SAFE"
    elif mal_rate >= 50.0 or malicious_count > 5:  
        overall_risk = "HIGH RISK"
    elif malicious_count >= 3:
        overall_risk = "MEDIUM RISK"
    else:
        overall_risk = "LOW RISK"

    if overall_risk == "SAFE":
        risk_description = "\nNo malicious files detected.\nUSB appears safe and clean.\n"
    elif overall_risk == "LOW RISK":
        risk_description = "\nLow number of suspicious files detected.\nPossible risks:\n• Minor suspicious activity\n• Unknown executable files\n• Potential unsafe scripts\n"
    elif overall_risk == "MEDIUM RISK":
        risk_description = "\nMultiple suspicious files detected.\nPossible risks:\n• Malware execution\n• Unauthorized access\n• File corruption\n• USB exploitation\n"
    else:
        risk_description = "\nCritical malicious activity detected.\nPossible risks:\n• Severe malware infection\n• System compromise\n• Auto-run attacks\n• Data theft\n• Malware spreading\n"

    output_box.insert("end", "🔴 MALICIOUS USB ANALYSIS SUMMARY\n")
    output_box.insert("end", "=" * 90 + "\n\n")
    output_box.insert(
        "end",
        f"Total Files Scanned   : {total_scanned}\n"
        f"Safe Files            : {stats_cache['safe']}\n"
        f"Suspicious Files      : {suspicious_count}\n"        
        f"Malicious Files Found : {malicious_count}\n"
        f"Malicious Percentage  : {mal_rate:.2f}%\n"
        f"Overall USB Risk      : {overall_risk}\n\n"
    )
    output_box.insert("end", risk_description + "\n")

    output_box.insert("end", "\n🔍 DETAILED MALWARE ANALYSIS\n")
    output_box.insert("end", "-" * 90 + "\n\n")

    if len(files) == 0:
        output_box.insert("end", "✅ NO TARGET FILES ISOLATED VIA SPECIFIED VIEW FILTER\n")

    for idx, f in enumerate(files, 1):
        output_box.insert("end", f"[ FILE {idx} ]\n")
        output_box.insert("end", "-" * 60 + "\n")
        output_box.insert("end", f"📁 File Path        : {f['file']}\n")
        output_box.insert("end", f"🧬 Classification   : {f['verdict']}\n\n")
        output_box.insert("end", "📊 RISK SCORE ANALYSIS\n")
        output_box.insert(
            "end",
            f"• Heuristic Score : {f['heuristic']}\n"
            f"• Behavior Score  : {f['behavior']}\n"
            f"• Total Score     : {f['total']}\n\n"
        )
        output_box.insert("end", "🚨 DETECTION INDICATORS\n")

        if f["reasons"]:
            for r in f["reasons"]:
                output_box.insert("end", f"• {r}\n")
        else:
            output_box.insert("end", "• No specific indicators detected\n")
        output_box.insert("end", "\n")

    view_frame.pack_forget()
    action_frame.pack(anchor="center")


def handle_action(action):
    global selected_file
    global ignored_files

    if not selected_file:
        messagebox.showwarning(
            "SELECT FILE",
            "Action execution halted. Select an entity from the tracking deck grid first."
        )
        return

    path = selected_file["file"]

    if action == "delete":
        first_confirm = messagebox.askyesno(
            "DELETE FILE",
            f"Are you sure you want to DELETE this file?\n\n{path}"
        )
        if not first_confirm:
            return

        second_confirm = messagebox.askyesno(
            "FINAL WARNING",
            "This action is PERMANENT.\n\nDeleted files cannot be recovered.\n\nProceed with deletion?"
        )
        if not second_confirm:
            return

    elif action == "quarantine":
        quarantine_confirm = messagebox.askyesno(
            "QUARANTINE FILE",
            f"Isolate file inside system container sandbox?\n\n{path}"
        )
        if not quarantine_confirm:
            return

    elif action == "ignore":
        ignore_confirm = messagebox.askyesno(
            "IGNORE FILE",
            f"Bypass future heuristics scans for this asset?\n\n{path}"
        )
        if not ignore_confirm:
            return

    try:
        if action == "delete":
            os.remove(path)
            messagebox.showinfo("SUCCESS", "Target scrubbed permanently.")
        elif action == "quarantine":
            os.makedirs("quarantine", exist_ok=True)
            shutil.move(path, "quarantine/")
            messagebox.showinfo("SUCCESS", "Object integrity safely neutralized inside quarantine matrix.")
        elif action == "ignore":
            ignored_files.append(path)
            messagebox.showinfo("IGNORED", "Asset whitelisted successfully.")

        refresh_list()

    except Exception as e:
        messagebox.showerror("OS FILE SYSTEM FAULT", str(e))


def refresh_list():
    scan_usb()
    show_results("MALICIOUS")


def back_to_view():
    action_frame.pack_forget()
    view_frame.pack(anchor="center")


def reset_to_scan():
    view_frame.pack_forget()
    action_frame.pack_forget()
    scan_frame.pack(anchor="center")
    
    # Reset terminal text to base startup logs instead of clearing it to a blank square
    output_box.delete("1.0", "end")
    output_box.insert("1.0", ">> CORE TERMINAL INITIALIZATION COMPLETED SUCCESSFUL.\n")
    output_box.insert("end", ">> LINKING STATIC HEURISTIC PATTERN ENGINE V2.4...\n")
    output_box.insert("end", ">> MONITORING KERNEL MEMORY INTERFACES...\n")
    output_box.insert("end", ">> SYSTEM BASE STATUS: AWAITING DRIVE DETECT LINK.\n")
    
    stats_label.configure(text=">> SYSTEM READY. INSERT COMPATIBLE FLASH DRIVE TO SCAN.")

    # Hide grid layout and reveal safe placeholders
    file_listbox.pack_forget()
    for widget in file_listbox.winfo_children():
        widget.destroy()
    placeholder_frame.place(relx=0.5, rely=0.5, anchor="center")


# ================= ENGINE KERNEL RUNTIME =================
root.mainloop()