import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from blake3 import blake3


CHUNK_SIZE = 1024 * 1024


class StandardBlake3HasherApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Standard BLAKE3 Hasher")
        self.geometry("640x220")
        self.minsize(560, 200)

        self.file_path_var = tk.StringVar()
        self.hash_var = tk.StringVar(value="Hash will appear here")
        self.status_var = tk.StringVar(value="Choose a file to hash")

        self._busy = False

        self._build_ui()

    def _build_ui(self) -> None:
        container = ttk.Frame(self, padding=16)
        container.pack(fill="both", expand=True)

        title = ttk.Label(container, text="Standard BLAKE3 Hasher", font=("Segoe UI", 16, "bold"))
        title.pack(anchor="w", pady=(0, 12))

        file_row = ttk.Frame(container)
        file_row.pack(fill="x", pady=(0, 10))

        path_entry = ttk.Entry(file_row, textvariable=self.file_path_var)
        path_entry.pack(side="left", fill="x", expand=True)

        browse_btn = ttk.Button(file_row, text="Browse", command=self.browse_file)
        browse_btn.pack(side="left", padx=(8, 0))

        action_row = ttk.Frame(container)
        action_row.pack(fill="x", pady=(0, 10))

        hash_btn = ttk.Button(action_row, text="Hash File", command=self.start_hashing)
        hash_btn.pack(side="left")

        copy_btn = ttk.Button(action_row, text="Copy Hash", command=self.copy_hash)
        copy_btn.pack(side="left", padx=(8, 0))

        hash_frame = ttk.LabelFrame(container, text="BLAKE3 (hex)", padding=10)
        hash_frame.pack(fill="x", expand=False)

        hash_entry = ttk.Entry(hash_frame, textvariable=self.hash_var)
        hash_entry.pack(fill="x", expand=True)

        status = ttk.Label(container, textvariable=self.status_var)
        status.pack(anchor="w", pady=(10, 0))

    def browse_file(self) -> None:
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.file_path_var.set(path)
            self.status_var.set("Ready to hash")

    def start_hashing(self) -> None:
        if self._busy:
            messagebox.showinfo("Busy", "Please wait for the current task to finish.")
            return

        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("No file selected", "Please choose a file first.")
            return

        if not os.path.isfile(file_path):
            messagebox.showerror("Invalid file", "The selected path is not a valid file.")
            return

        self._busy = True
        self.status_var.set("Hashing...")
        self.hash_var.set("Computing hash...")

        worker = threading.Thread(target=self._hash_file_worker, args=(file_path,), daemon=True)
        worker.start()

    def _hash_file_worker(self, file_path: str) -> None:
        try:
            digest = self._hash_file(file_path)
            self.after(0, lambda: self._on_hash_success(digest))
        except Exception as exc:
            self.after(0, lambda: self._on_hash_error(str(exc)))

    def _hash_file(self, file_path: str) -> str:
        hasher = blake3()
        with open(file_path, "rb") as file_handle:
            while True:
                chunk = file_handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def _on_hash_success(self, digest: str) -> None:
        self._busy = False
        self.hash_var.set(digest)
        self.status_var.set("Hash complete")

    def _on_hash_error(self, error_message: str) -> None:
        self._busy = False
        self.hash_var.set("Hash failed")
        self.status_var.set("Error while hashing")
        messagebox.showerror("Hashing error", error_message)

    def copy_hash(self) -> None:
        digest = self.hash_var.get().strip()
        if not digest or digest in {"Hash will appear here", "Computing hash...", "Hash failed"}:
            messagebox.showinfo("Nothing to copy", "Run a hash first.")
            return

        self.clipboard_clear()
        self.clipboard_append(digest)
        self.status_var.set("Hash copied to clipboard")


if __name__ == "__main__":
    app = StandardBlake3HasherApp()
    app.mainloop()