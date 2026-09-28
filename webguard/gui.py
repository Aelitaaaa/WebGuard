import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from urllib.parse import urlsplit

from .scanner import run_scan
from .reporter import default_report_paths, write_json, write_html

def launch():
    root = tk.Tk()
    root.title("WebGuard v0.1")
    root.geometry("820x620")
    root.minsize(760, 560)

    target = tk.StringVar(value="https://")
    authorized = tk.BooleanVar(value=False)
    max_pages = tk.IntVar(value=10)
    delay = tk.DoubleVar(value=0.8)
    safe_active = tk.BooleanVar(value=False)
    report_dir = tk.StringVar(value=str(Path.cwd() / "reports"))
    status = tk.StringVar(value="Siap.")

    frm = ttk.Frame(root, padding=18)
    frm.pack(fill="both", expand=True)

    ttk.Label(frm, text="WebGuard", font=("Segoe UI", 22, "bold")).pack(anchor="w")
    ttk.Label(frm, text="Authorized non-destructive web security assessment").pack(anchor="w", pady=(0, 18))

    grid = ttk.Frame(frm)
    grid.pack(fill="x")

    ttk.Label(grid, text="Target URL").grid(row=0, column=0, sticky="w", pady=6)
    ttk.Entry(grid, textvariable=target).grid(row=0, column=1, sticky="ew", pady=6)

    ttk.Label(grid, text="Max pages").grid(row=1, column=0, sticky="w", pady=6)
    ttk.Spinbox(grid, from_=1, to=50, textvariable=max_pages, width=8).grid(row=1, column=1, sticky="w", pady=6)

    ttk.Label(grid, text="Delay/request").grid(row=2, column=0, sticky="w", pady=6)
    ttk.Spinbox(grid, from_=0.2, to=10, increment=0.1, textvariable=delay, width=8).grid(row=2, column=1, sticky="w", pady=6)

    ttk.Label(grid, text="Report folder").grid(row=3, column=0, sticky="w", pady=6)
    report_row = ttk.Frame(grid)
    report_row.grid(row=3, column=1, sticky="ew")
    ttk.Entry(report_row, textvariable=report_dir).pack(side="left", fill="x", expand=True)
    ttk.Button(report_row, text="Browse", command=lambda: report_dir.set(filedialog.askdirectory() or report_dir.get())).pack(side="left", padx=(8,0))

    ttk.Checkbutton(
        frm,
        variable=authorized,
        text="Saya memiliki izin eksplisit untuk menguji target ini.",
    ).pack(anchor="w", pady=(15, 4))

    ttk.Checkbutton(
        frm,
        variable=safe_active,
        text="Aktifkan safe-active CORS reflection check (benign request).",
    ).pack(anchor="w")

    output = tk.Text(frm, height=18, wrap="word")
    output.pack(fill="both", expand=True, pady=16)

    ttk.Label(frm, textvariable=status).pack(anchor="w")

    def log(text):
        output.insert("end", text + "\n")
        output.see("end")

    def worker():
        try:
            result = run_scan(
                target.get(),
                max_pages=max_pages.get(),
                delay=delay.get(),
                safe_active=safe_active.get(),
            )
            host = urlsplit(result.target).hostname or "target"
            j, h = default_report_paths(report_dir.get(), host)
            write_json(result, j)
            write_html(result, h)

            counts = {}
            for f in result.findings:
                counts[f.severity] = counts.get(f.severity, 0) + 1

            root.after(0, lambda: log(
                f"Selesai. Pages={len(result.pages_scanned)} | "
                f"High={counts.get('HIGH',0)} Medium={counts.get('MEDIUM',0)} "
                f"Low={counts.get('LOW',0)} Info={counts.get('INFO',0)}"
            ))
            root.after(0, lambda: log(f"HTML: {h}"))
            root.after(0, lambda: log(f"JSON: {j}"))
            root.after(0, lambda: status.set("Scan selesai."))
        except Exception as e:
            root.after(0, lambda: status.set("Scan gagal."))
            root.after(0, lambda msg=str(e): messagebox.showerror("WebGuard", msg))

    def start():
        if not authorized.get():
            messagebox.showwarning("Authorization", "Konfirmasi izin eksplisit sebelum menjalankan scan.")
            return
        output.delete("1.0", "end")
        status.set("Scanning...")
        log("Memulai scan aman...")
        threading.Thread(target=worker, daemon=True).start()

    ttk.Button(frm, text="Start Authorized Scan", command=start).pack(anchor="e")
    grid.columnconfigure(1, weight=1)
    root.mainloop()
