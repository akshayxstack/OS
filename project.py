import os
import hashlib
import shutil
import time
from pathlib import Path
from collections import defaultdict

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None


class FileSystemTool:
    

    def __init__(self):
        self.root_path = None
        self.files = []          
        self.empty_dirs = []    
        self.duplicates = []     


    def set_root(self, root_path):
        self.root_path = Path(root_path)

    def scan(self, log_func=print):
        
        if not self.root_path or not self.root_path.exists():
            raise ValueError("Root path not set or does not exist.")

        self.files = []
        self.empty_dirs = []
        self.duplicates = []

        log_func(f"Scanning: {self.root_path}\n")
        start_time = time.time()

        for dirpath, dirnames, filenames in os.walk(self.root_path):
            dir_path = Path(dirpath)

            # empty dir = no files and no subdirs
            if not dirnames and not filenames:
                self.empty_dirs.append(dir_path)

            for name in filenames:
                file_path = dir_path / name
                try:
                    stat = file_path.stat()
                    size = stat.st_size
                    ext = file_path.suffix.lower()
                    created = stat.st_ctime
                    modified = stat.st_mtime

                    file_info = {
                        "path": file_path,
                        "size": size,
                        "ext": ext,
                        "created": created,
                        "modified": modified,
                        # hash is computed later only for candidates
                        "hash": None,
                    }
                    self.files.append(file_info)
                except Exception as e:
                    log_func(f"[WARN] Cannot access {file_path}: {e}")

        elapsed = time.time() - start_time
        log_func(f"\nScan complete. Files found: {len(self.files)}")
        log_func(f"Empty directories: {len(self.empty_dirs)}")
        log_func(f"Time taken: {elapsed:.2f} seconds\n")


    @staticmethod
    def compute_hash(path, block_size=65536):
        
        hasher = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                data = f.read(block_size)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()

    def find_duplicates(self, log_func=print):
       
        self.duplicates = []
        if not self.files:
            log_func("No files to analyze. Please scan first.\n")
            return

        log_func("Finding duplicate files...\n")
        start_time = time.time()

       
        size_map = defaultdict(list)
        for info in self.files:
            size_map[info["size"]].append(info)

       
        for size, group in size_map.items():
            if len(group) < 2 or size == 0:
                continue  

            hash_map = defaultdict(list)
            for info in group:
                try:
                    file_hash = self.compute_hash(info["path"])
                    info["hash"] = file_hash
                    hash_map[file_hash].append(info)
                except Exception as e:
                    log_func(f"[WARN] Cannot hash {info['path']}: {e}")

            for h, dup_group in hash_map.items():
                if len(dup_group) > 1:
                    
                    paths = [f["path"] for f in dup_group]
                    self.duplicates.append(paths)

        elapsed = time.time() - start_time
        total_dup_files = sum(len(g) for g in self.duplicates)
        log_func(f"Duplicate search complete.")
        log_func(f"Duplicate groups: {len(self.duplicates)}")
        log_func(f"Total duplicate files: {total_dup_files}")
        log_func(f"Time taken: {elapsed:.2f} seconds\n")

    

    def get_summary(self):
        total_size = sum(f["size"] for f in self.files)
        file_count = len(self.files)
        empty_dir_count = len(self.empty_dirs)
        dup_group_count = len(self.duplicates)
        dup_file_count = sum(len(g) for g in self.duplicates)
        return {
            "total_files": file_count,
            "total_size": total_size,
            "empty_dirs": empty_dir_count,
            "duplicate_groups": dup_group_count,
            "duplicate_files": dup_file_count,
        }


    def delete_empty_dirs(self, log_func=print):
        deleted = 0
        for d in sorted(self.empty_dirs, key=lambda p: len(str(p)), reverse=True):
            try:
                os.rmdir(d)
                log_func(f"[DELETE] Empty dir removed: {d}")
                deleted += 1
            except OSError:
                # directory not empty now or other error
                continue
        log_func(f"\nEmpty directories deleted: {deleted}\n")
        return deleted

    def delete_duplicates_keep_one(self, log_func=print):
       
        if not self.duplicates:
            log_func("No duplicates to delete.\n")
            return 0

        deleted_count = 0
        for group in self.duplicates:
            
            for path in group[1:]:
                try:
                    os.remove(path)
                    log_func(f"[DELETE] Duplicate removed: {path}")
                    deleted_count += 1
                except Exception as e:
                    log_func(f"[WARN] Could not delete {path}: {e}")
        log_func(f"\nTotal duplicate files deleted: {deleted_count}\n")
        return deleted_count

    def organize_by_type(self, log_func=print):
       
        if not self.root_path:
            log_func("Root path not set.\n")
            return

        log_func("Organizing files by type...\n")

        
        image_exts = {".jpg", ".jpeg", ".png", ".gif", ".bmp"}
        doc_exts = {".pdf", ".doc", ".docx", ".txt", ".ppt", ".pptx", ".xls", ".xlsx"}
        video_exts = {".mp4", ".avi", ".mkv", ".mov"}
        audio_exts = {".mp3", ".wav", ".aac"}

        category_dirs = {
            "Images": image_exts,
            "Documents": doc_exts,
            "Videos": video_exts,
            "Audio": audio_exts,
        }

        moved_count = 0

        for info in self.files:
            path = info["path"]
            ext = info["ext"]
            try:
                path.relative_to(self.root_path)
            except ValueError:
                continue

            category = None
            for cat, exts in category_dirs.items():
                if ext in exts:
                    category = cat
                    break

            if category is None:
                category = "Others"

            target_dir = self.root_path / category
            target_dir.mkdir(exist_ok=True)

            target_path = target_dir / path.name
            if target_path == path:
                continue  

            if target_path.exists():
                target_path = target_dir / f"{path.stem}_copy{path.suffix}"

            try:
                shutil.move(str(path), str(target_path))
                log_func(f"[MOVE] {path} -> {target_path}")
                moved_count += 1
            except Exception as e:
                log_func(f"[WARN] Could not move {path}: {e}")

        log_func(f"\nTotal files moved: {moved_count}\n")
        return moved_count


    def get_size_by_extension(self):
        data = defaultdict(int)
        for f in self.files:
            ext = f["ext"] or "NO_EXT"
            data[ext] += f["size"]
        return data

    def get_size_by_top_dirs(self, top_n=5):
        data = defaultdict(int)
        if not self.root_path:
            return data

        root_str = str(self.root_path)
        for f in self.files:
            try:
                rel = f["path"].relative_to(self.root_path)
            except ValueError:
                continue
            parts = rel.parts
            if len(parts) == 0:
                key = "."
            else:
                key = parts[0]
            data[key] += f["size"]

        sorted_items = sorted(data.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_items[:top_n])


class AppGUI:
    

    def __init__(self, root):
        self.root = root
        self.root.title("File System Recovery and Optimization Tool")
        self.root.geometry("800x600")

        self.tool = FileSystemTool()

        self.create_widgets()

    def create_widgets(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(top_frame, text="Root Folder:").pack(side=tk.LEFT)

        self.path_entry = tk.Entry(top_frame, width=60)
        self.path_entry.pack(side=tk.LEFT, padx=5)

        browse_btn = tk.Button(top_frame, text="Browse", command=self.browse_folder)
        browse_btn.pack(side=tk.LEFT)

        mid_frame = tk.Frame(self.root)
        mid_frame.pack(fill=tk.X, padx=10, pady=5)

        scan_btn = tk.Button(mid_frame, text="Scan", width=12, command=self.scan_action)
        scan_btn.pack(side=tk.LEFT, padx=5)

        dup_btn = tk.Button(mid_frame, text="Find Duplicates", width=15,
                            command=self.find_duplicates_action)
        dup_btn.pack(side=tk.LEFT, padx=5)

        summary_btn = tk.Button(mid_frame, text="Show Summary", width=15,
                                command=self.show_summary_action)
        summary_btn.pack(side=tk.LEFT, padx=5)

        del_empty_btn = tk.Button(mid_frame, text="Delete Empty Dirs", width=18,
                                  command=self.delete_empty_dirs_action)
        del_empty_btn.pack(side=tk.LEFT, padx=5)

        del_dup_btn = tk.Button(mid_frame, text="Delete Duplicates", width=15,
                                command=self.delete_duplicates_action)
        del_dup_btn.pack(side=tk.LEFT, padx=5)

        organize_btn = tk.Button(mid_frame, text="Organize by Type", width=15,
                                 command=self.organize_action)
        organize_btn.pack(side=tk.LEFT, padx=5)

        chart_btn = tk.Button(mid_frame, text="Show Charts", width=12,
                              command=self.show_charts_action)
        chart_btn.pack(side=tk.LEFT, padx=5)

        self.log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        footer = tk.Label(
            self.root,
            text="Note: Be careful when deleting/moving files. Test on sample folders first.",
            fg="red"
        )
        footer.pack(side=tk.BOTTOM, pady=5)


    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()


    def browse_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def scan_action(self):
        path = self.path_entry.get().strip()
        if not path:
            messagebox.showwarning("Warning", "Please select a root folder.")
            return

        if not os.path.exists(path):
            messagebox.showerror("Error", "Selected path does not exist.")
            return

        self.log_text.delete("1.0", tk.END)
        self.tool.set_root(path)
        try:
            self.tool.scan(log_func=self.log)
            self.log("Scan finished.\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def find_duplicates_action(self):
        if not self.tool.files:
            messagebox.showwarning("Warning", "Please scan first.")
            return
        self.tool.find_duplicates(log_func=self.log)

        if not self.tool.duplicates:
            self.log("No duplicate files found.\n")
            return

        self.log("Duplicate groups (showing up to first 3 groups):")
        for i, group in enumerate(self.tool.duplicates[:3], start=1):
            self.log(f"Group {i}:")
            for p in group:
                self.log(f"  {p}")
        self.log("...\n")

    def show_summary_action(self):
        if not self.tool.files:
            messagebox.showwarning("Warning", "Please scan first.")
            return
        summary = self.tool.get_summary()

        def format_size(bytes_val):
            units = ["B", "KB", "MB", "GB", "TB"]
            size = float(bytes_val)
            unit = 0
            while size >= 1024 and unit < len(units) - 1:
                size /= 1024.0
                unit += 1
            return f"{size:.2f} {units[unit]}"

        self.log("\n--- SUMMARY ---")
        self.log(f"Root: {self.tool.root_path}")
        self.log(f"Total files: {summary['total_files']}")
        self.log(f"Total size: {format_size(summary['total_size'])}")
        self.log(f"Empty directories: {summary['empty_dirs']}")
        self.log(f"Duplicate groups: {summary['duplicate_groups']}")
        self.log(f"Duplicate files (total): {summary['duplicate_files']}")
        self.log("----------------\n")

    def delete_empty_dirs_action(self):
        if not self.tool.empty_dirs:
            self.log("No empty directories found or scan not done.\n")
            return

        ans = messagebox.askyesno(
            "Confirm",
            f"Are you sure you want to delete {len(self.tool.empty_dirs)} empty directories?"
        )
        if not ans:
            return

        self.tool.delete_empty_dirs(log_func=self.log)
        self.log("You may run scan again to refresh data.\n")

    def delete_duplicates_action(self):
        if not self.tool.duplicates:
            self.log("No duplicate files to delete. Run 'Find Duplicates' first.\n")
            return

        total_dup_files = sum(len(g) for g in self.tool.duplicates)
        ans = messagebox.askyesno(
            "Confirm",
            f"Delete duplicates? (Total duplicate file entries: {total_dup_files}. "
            f"One file from each group will be kept.)"
        )
        if not ans:
            return

        self.tool.delete_duplicates_keep_one(log_func=self.log)
        self.log("You may run scan again to refresh data.\n")

    def organize_action(self):
        if not self.tool.files:
            self.log("No files in memory. Please scan first.\n")
            return

        ans = messagebox.askyesno(
            "Confirm",
            "Organize files by type into subfolders (Images, Documents, Videos, Audio, Others)?"
        )
        if not ans:
            return

        self.tool.organize_by_type(log_func=self.log)
        self.log("You may run scan again to refresh data.\n")

    def show_charts_action(self):
        if plt is None:
            messagebox.showerror(
                "Error",
                "matplotlib is not installed. Install it with 'pip install matplotlib'."
            )
            return

        if not self.tool.files:
            messagebox.showwarning("Warning", "Please scan first.")
            return

        # Pie chart: size by extension
        size_by_ext = self.tool.get_size_by_extension()
        labels = list(size_by_ext.keys())
        sizes = list(size_by_ext.values())

        if sizes:
            plt.figure()
            plt.pie(sizes, labels=labels, autopct="%1.1f%%")
            plt.title("Disk Usage by File Extension")

        size_by_dir = self.tool.get_size_by_top_dirs(top_n=5)
        if size_by_dir:
            plt.figure()
            dirs = list(size_by_dir.keys())
            vals = list(size_by_dir.values())
            plt.bar(dirs, vals)
            plt.title("Top Directories by Size")
            plt.xlabel("Directory (first level under root)")
            plt.ylabel("Size (bytes)")
            plt.xticks(rotation=45)

        if sizes or size_by_dir:
            plt.tight_layout()
            plt.show()
        else:
            self.log("No data to show in charts.\n")


def main():
    root = tk.Tk()
    app = AppGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
