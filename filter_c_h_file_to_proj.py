import os
import shutil

# =====================================================
# 🔧 使用者自定義路徑
SRC_FOLDER_PATH = "/user/abc"      # <-- 改這裡
EXTS = {".c", ".h"}                # 要保留的副檔名
# =====================================================

# 根據 SRC_FOLDER_PATH 決定輸出路徑
PARENT_DIR = os.path.dirname(SRC_FOLDER_PATH.rstrip("/"))
BASENAME = os.path.basename(SRC_FOLDER_PATH.rstrip("/"))
DST_FOLDER_PATH = os.path.join(PARENT_DIR, f"cp_{BASENAME}")

def copy_c_and_h(src_dir, dst_dir):
    for root, dirs, files in os.walk(src_dir):
        rel_path = os.path.relpath(root, src_dir)
        target_dir = os.path.join(dst_dir, rel_path)

        selected_files = [
            f for f in files if os.path.splitext(f)[1].lower() in EXTS
        ]

        if selected_files:
            os.makedirs(target_dir, exist_ok=True)

        for file in selected_files:
            src_file = os.path.join(root, file)
            dst_file = os.path.join(target_dir, file)
            shutil.copy2(src_file, dst_file)
            print(f"Copied: {src_file} -> {dst_file}")

if __name__ == "__main__":
    print(f"Source folder : {SRC_FOLDER_PATH}")
    print(f"Target folder : {DST_FOLDER_PATH}")

    if not os.path.exists(SRC_FOLDER_PATH):
        print("❌ Source folder does not exist.")
        exit(1)

    if os.path.exists(DST_FOLDER_PATH):
        print(f"⚠️ Target folder already exists. Removing...")
        shutil.rmtree(DST_FOLDER_PATH)

    os.makedirs(DST_FOLDER_PATH, exist_ok=True)
    copy_c_and_h(SRC_FOLDER_PATH, DST_FOLDER_PATH)
    print("✅ Done! Only .c / .h files were copied.")