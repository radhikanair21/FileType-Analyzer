import tkinter as tk
from tkinter import filedialog, messagebox
import threading
from datetime import datetime
from file_analyzer import FileTypeAnalyzer


class RoundBtn(tk.Canvas):
    """Rounded button"""
    def __init__(self, parent, text, cmd, bg='#7C3AED', hover='#9333EA', w=160, h=48):
        super().__init__(parent, width=w, height=h, bg=parent['bg'], highlightthickness=0)
        self.cmd, self.bg, self.hbg, self.txt, self.w, self.h, self.on = cmd, bg, hover, text, w, h, True
        self._draw(bg)
        self.bind('<Button-1>', lambda e: self.on and cmd())
        self.bind('<Enter>', lambda e: self.on and self._draw(hover))
        self.bind('<Leave>', lambda e: self._draw(bg if self.on else '#2A2A3E'))
    
    def _draw(self, c):
        self.delete('all')
        r = 12
        for x, y, s in [(0,0,90), (self.w-r*2,0,0), (0,self.h-r*2,180), (self.w-r*2,self.h-r*2,270)]:
            self.create_arc(x, y, x+r*2, y+r*2, start=s, extent=90, fill=c, outline='')
        self.create_rectangle(r, 0, self.w-r, self.h, fill=c, outline='')
        self.create_rectangle(0, r, self.w, self.h-r, fill=c, outline='')
        self.create_text(self.w/2, self.h/2, text=self.txt, fill='white', font=('Segoe UI', 10, 'bold'))
    
    def set_state(self, s):
        self.on = (s == 'normal')
        self._draw(self.bg if self.on else '#2A2A3E')


class App:
    def __init__(self, root):
        self.root = root
        root.title("FileType Analyzer")
        root.geometry("1000x780")
        root.resizable(False, False)
        
        self.c = {'bg':'#0D0D1A', 'p':'#1A1A2E', 'pl':'#252540', 'ac':'#7C3AED', 
                  'cy':'#06B6D4', 'txt':'#F8FAFC', 'dim':'#94A3B8', 'ok':'#10B981', 
                  'bad':'#EF4444', 'bor':'#2E2E48'}
        root.configure(bg=self.c['bg'])
        
        self.analyzer = FileTypeAnalyzer()
        self.result = None
        self._build()
    
    def _build(self):
        m = tk.Frame(self.root, bg=self.c['bg'])
        m.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Header
        tk.Label(m, text="🔐 FileType Analyzer", bg=self.c['bg'], fg=self.c['txt'],
                font=('Segoe UI', 28, 'bold')).pack(pady=(0,8))
        tk.Label(m, text="Advanced Signature Detection & Forensic Analysis",
                bg=self.c['bg'], fg=self.c['dim'], font=('Segoe UI', 11)).pack(pady=(0,30))
        
        # File panel
        fp = tk.Frame(m, bg=self.c['p'], highlightbackground=self.c['bor'], highlightthickness=1)
        fp.pack(fill='x', pady=(0,20))
        tk.Label(fp, text="📁  FILE SELECTION", bg=self.c['p'], fg=self.c['cy'],
                font=('Segoe UI', 11, 'bold')).pack(anchor='w', padx=20, pady=(20,15))
        
        pf = tk.Frame(fp, bg=self.c['p'])
        pf.pack(fill='x', padx=20, pady=(0,20))
        pi = tk.Frame(pf, bg=self.c['pl'], highlightbackground=self.c['bor'], highlightthickness=1)
        pi.pack(side='left', fill='x', expand=True)
        
        self.path = tk.StringVar(value="No file selected")
        tk.Label(pi, textvariable=self.path, bg=self.c['pl'], fg=self.c['cy'],
                font=('Consolas', 10), anchor='w', padx=18, pady=14).pack(fill='x')
        
        RoundBtn(pf, "Browse File", self.select, self.c['ac'], '#9333EA', 140, 50).pack(side='right', padx=(15,0))
        
        # Results panel
        rp = tk.Frame(m, bg=self.c['p'], highlightbackground=self.c['bor'], highlightthickness=1)
        rp.pack(fill='both', expand=True, pady=(0,20))
        tk.Label(rp, text="📊  ANALYSIS RESULTS", bg=self.c['p'], fg=self.c['cy'],
                font=('Segoe UI', 11, 'bold')).pack(anchor='w', padx=20, pady=(20,15))
        
        rc = tk.Frame(rp, bg=self.c['p'])
        rc.pack(fill='both', expand=True, padx=20, pady=(0,20))
        
        cv = tk.Canvas(rc, bg=self.c['pl'], highlightthickness=0)
        sb = tk.Scrollbar(rc, orient='vertical', command=cv.yview)
        self.rf = tk.Frame(cv, bg=self.c['pl'])
        self.rf.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.create_window((0,0), window=self.rf, anchor='nw')
        cv.configure(yscrollcommand=sb.set)
        cv.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')
        
        self._empty()
        
        # Buttons
        bf = tk.Frame(m, bg=self.c['bg'])
        bf.pack(fill='x')
        self.ab = RoundBtn(bf, "🔍 Analyze File", self.analyze, self.c['ac'], '#9333EA', 170, 52)
        self.ab.pack(side='left', padx=(0,15))
        self.ab.set_state('disabled')
        self.eb = RoundBtn(bf, "💾 Export Report", self.export, self.c['cy'], '#0891B2', 170, 52)
        self.eb.pack(side='left', padx=(0,15))
        self.eb.set_state('disabled')
        RoundBtn(bf, "🗑️ Clear", self.clear, '#475569', '#64748B', 130, 52).pack(side='left')
    
    def _empty(self):
        for w in self.rf.winfo_children(): w.destroy()
        e = tk.Frame(self.rf, bg=self.c['pl'])
        e.pack(expand=True, fill='both', pady=80)
        tk.Label(e, text="🔍", bg=self.c['pl'], font=('Segoe UI', 56)).pack()
        tk.Label(e, text="Select a file to begin analysis", bg=self.c['pl'],
                fg=self.c['dim'], font=('Segoe UI', 13)).pack(pady=(15,0))
    
    def select(self):
        p = filedialog.askopenfilename(title="Select file", filetypes=[("All Files", "*.*")])
        if p:
            self.path.set(p)
            self.ab.set_state('normal')
            self.result = None
            self.eb.set_state('disabled')
    
    def analyze(self):
        if self.path.get() == "No file selected":
            return messagebox.showwarning("No File", "Please select a file first")
        self.ab.set_state('disabled')
        threading.Thread(target=self._run, daemon=True).start()
    
    def _run(self):
        try:
            self.result = self.analyzer.analyze_file(self.path.get())
            self.root.after(0, self._show)
            self.root.after(0, lambda: self.ab.set_state('normal'))
            self.root.after(0, lambda: self.eb.set_state('normal'))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.root.after(0, lambda: self.ab.set_state('normal'))
    
    def _show(self):
        for w in self.rf.winfo_children(): w.destroy()
        con = tk.Frame(self.rf, bg=self.c['pl'])
        con.pack(fill='both', expand=True, padx=20, pady=20)
        
        for lbl, val in [("📄 File Name", self.result['filename']), ("🏷️ Extension", self.result['extension']),
                         ("🔍 Detected Type", self.result['detected_type']), ("🧬 Magic Signature", self.result['signature']),
                         ("📦 File Size", f"{self.result['file_size']:,} bytes"), ("🔐 SHA-256", self.result['sha256'])]:
            it = tk.Frame(con, bg=self.c['p'], highlightbackground=self.c['bor'], highlightthickness=1)
            it.pack(fill='x', pady=7)
            tk.Label(it, text=lbl, bg=self.c['p'], fg=self.c['dim'],
                    font=('Segoe UI', 9, 'bold'), anchor='w').pack(anchor='w', padx=18, pady=(12,5))
            
            if len(str(val)) > 75:
                tx = tk.Text(it, height=2, wrap='word', bg=self.c['p'], fg=self.c['cy'],
                            font=('Consolas', 9), relief='flat', borderwidth=0)
                tx.insert('1.0', val)
                tx.config(state='disabled')
                tx.pack(fill='x', padx=18, pady=(0,12))
            else:
                tk.Label(it, text=val, bg=self.c['p'], fg=self.c['cy'],
                        font=('Consolas', 10, 'bold'), anchor='w').pack(anchor='w', padx=18, pady=(0,12))
        
        # Status
        bad = self.result['is_suspicious']
        bn = tk.Frame(con, bg='#2D1F1F' if bad else '#1F2D23',
                     highlightbackground=self.c['bad'] if bad else self.c['ok'], highlightthickness=2)
        bn.pack(fill='x', pady=(20,0))
        tk.Label(bn, text="⚠️" if bad else "✓", bg=bn['bg'],
                fg=self.c['bad'] if bad else self.c['ok'], font=('Segoe UI', 32)).pack(pady=(20,8))
        tk.Label(bn, text="SUSPICIOUS FILE DETECTED" if bad else "FILE SIGNATURE VALID",
                bg=bn['bg'], fg=self.c['bad'] if bad else self.c['ok'],
                font=('Segoe UI', 14, 'bold')).pack()
        tk.Label(bn, text=self.result['mismatch_reason'] if bad else "Extension matches detected type",
                bg=bn['bg'], fg=self.c['dim'], font=('Segoe UI', 10)).pack(pady=(8,20))
    
    def export(self):
        if not self.result:
            return messagebox.showwarning("No Results", "No analysis results to export")
        p = filedialog.asksaveasfilename(title="Save Report", defaultextension=".txt",
                                        filetypes=[("Text Files", "*.txt")])
        if p:
            try:
                r = self.result
                report = f"""
╔══════════════════════ FILE ANALYZER REPORT ══════════════════════╗
║ Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}         
╠════════════════════════ FILE INFORMATION ════════════════════════╣
║ Name: {r['filename']}                                            
║ Path: {r['filepath']}                                            
║ Size: {r['file_size']} bytes ({r['file_size']/1024:.2f} KB)      
║ Extension: {r['extension']}                                      
╠══════════════════════ SIGNATURE ANALYSIS ════════════════════════╣
║ Detected Type: {r['detected_type']}                              
║ Magic Signature: {r['signature']}                                
╠════════════════════════ HASH DETAILS ════════════════════════════╣
║ SHA-256: {r['sha256']}                                           
╠══════════════════════ THREAT ASSESSMENT ═════════════════════════╣
║ Status: {"⚠️ Suspicious" if r['is_suspicious'] else "✓ Safe"}      
║ Detail: {r['mismatch_reason'] if r['is_suspicious'] else "None"} 
╚═══════════════════════════════════════════════════════════════════╝
"""
                with open(p, 'w', encoding='utf-8') as f:
                    f.write(report)
                messagebox.showinfo("Success", f"Report saved!\n\n{p}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def clear(self):
        self.path.set("No file selected")
        self.result = None
        self.ab.set_state('disabled')
        self.eb.set_state('disabled')
        self._empty()


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
