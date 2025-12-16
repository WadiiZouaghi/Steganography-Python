import os, struct, argparse, hashlib, threading, queue, sys
from PIL import Image
from typing import Optional
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2.low_level import hash_secret_raw, Type
import customtkinter as ctk
from customtkinter import CTkImage
from tkinter import filedialog, messagebox

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
ARGON2_TIME = 3
ARGON2_MEMORY = 65536
ARGON2_PARALLELISM = 1
MAGIC = b"STG2"
# header: magic(4s), enc_flag(B), salt_len(B), nonce_len(B), ct_len(I)
HEADER_STRUCT = ">4sBBBI"
HEADER_LEN = struct.calcsize(HEADER_STRUCT) 
LSB_PER_CHANNEL = 1
CHANNELS = 3
# ---------------- CRYPTO ----------------
def derive_key(pw: str, salt: bytes) -> bytes:
    return hash_secret_raw(pw.encode(), salt, ARGON2_TIME, ARGON2_MEMORY, ARGON2_PARALLELISM, KEY_LEN, Type.ID)
def encrypt(plaintext: bytes, pw: str):
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(pw, salt)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return salt, nonce, ct
def decrypt(ct: bytes, salt: bytes, nonce: bytes, pw: str) -> bytes:
    key = derive_key(pw, salt)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
def bits_from_bytes(data: bytes) -> np.ndarray:
    if not data: return np.zeros(0, dtype=np.uint8)
    arr = np.frombuffer(data, np.uint8)
    return ((arr[:, None] & (1 << np.arange(7, -1, -1))) > 0).astype(np.uint8).reshape(-1)
def bytes_from_bits(bits: np.ndarray) -> bytes:
    if not bits.size: return b""
    b = np.asarray(bits, dtype=np.uint8).reshape(-1, 8)
    return bytes((b << np.arange(7, -1, -1)).sum(axis=1).astype(np.uint8).tolist())
# ---------------- IMAGE IO ----------------
def load_img(path: str) -> np.ndarray:
    return np.array(Image.open(path).convert("RGB"), dtype=np.uint8)
def save_img(arr: np.ndarray, path: str) -> None:
    Image.fromarray(arr).save(path)
def seedMaker(salt: bytes, nonce: bytes) -> int:
    h = hashlib.sha256(salt + nonce).digest()
    return int.from_bytes(h, "big") & ((1 << 64) - 1)
# ---------------- EMBED / EXTRACT (RGB + PRNG) ----------------
def embed_payload_into_flat(flat_bytes: np.ndarray, payload_bits: np.ndarray, salt: bytes, nonce: bytes, header_bits_len: int):
    total_slots = flat_bytes.size
    assert payload_bits.size <= total_slots, "payload_bits longer than flat capacity (checked earlier)"
    # positions available after reserved header region
    start = header_bits_len
    available = total_slots - start
    ct_bits = payload_bits[start:]
    if ct_bits.size == 0:
        return flat_bytes  # nothing to do

    if ct_bits.size > available:
        raise ValueError("Not enough capacity for ciphertext bits after header reservation")

    rng = np.random.default_rng(seedMaker(salt, nonce))
    perm = rng.permutation(np.arange(start, total_slots))[:ct_bits.size]
    flat_bytes[perm] = (flat_bytes[perm] & 0xFE) | ct_bits
    return flat_bytes
def extract_payload_bits_from_flat(flat_bytes: np.ndarray, salt: bytes, nonce: bytes, header_bits_len: int, ct_bits_len: int):
    total_slots = flat_bytes.size
    start = header_bits_len
    available = total_slots - start
    if ct_bits_len == 0:
        return np.zeros(0, dtype=np.uint8)
    if ct_bits_len > available:
        raise ValueError("Image does not contain enough embedded bits (possible corruption or wrong password).")
    rng = np.random.default_rng(seedMaker(salt, nonce))
    perm = rng.permutation(np.arange(start, total_slots))[:ct_bits_len]
    return (flat_bytes[perm] & 1).astype(np.uint8)
def build_payload(secret: bytes, pw: Optional[str]):
    if pw:
        salt, nonce, ct = encrypt(secret, pw)
        enc_flag = 1
    else:
        salt = b""
        nonce = b""
        ct = secret
        enc_flag = 0
    header = struct.pack(HEADER_STRUCT, MAGIC, enc_flag, len(salt), len(nonce), len(ct))
    payload = header + salt + nonce + ct
    return payload, salt, nonce, ct
def hide_secret(img_path: str, secret_path: str, out_path: str, pw: Optional[str], verbose: bool=False) -> int:
    arr = load_img(img_path)
    # capacity in bits = pixels * channels * LSB_PER_CHANNEL
    pixels = arr.shape[0] * arr.shape[1]
    total_slots = pixels * CHANNELS * LSB_PER_CHANNEL  # bits capacity
    capacity_bytes = total_slots // 8
    secret = open(secret_path, "rb").read()
    filename = os.path.basename(secret_path)
    filename_bytes = filename.encode()
    filename_len = len(filename_bytes)
    payload_data = filename_len.to_bytes(4, 'big') + filename_bytes + secret
    payload, salt, nonce, ct = build_payload(payload_data, pw)
    payload_bits = bits_from_bytes(payload)

    if payload_bits.size > total_slots:
        raise ValueError(f"Payload too large to hide ({len(payload)} bytes) in image (capacity {capacity_bytes} bytes).")
    # header bits length (header+salt+nonce) in bits
    header_bits_len = (HEADER_LEN + len(salt) + len(nonce)) * 8
    flat = arr.reshape(-1, 3).astype(np.uint8).flatten() # [R0,G0,B0,R1,G1,B1,...]
    header_part = payload_bits[:header_bits_len]
    if header_part.size:
        flat[:header_bits_len] = (flat[:header_bits_len] & 0xFE) | header_part
    # embed ciphertext bits pseudo-randomly using salt+nonce
    flat = embed_payload_into_flat(flat, payload_bits, salt, nonce, header_bits_len)
    arr_out = flat.reshape(arr.shape)
    save_img(arr_out, out_path)
    if verbose:
        print(f"[ok] Embedded {len(payload)} bytes into '{out_path}' (capacity {capacity_bytes} bytes)")
    return len(payload)
def extract_secret(img_path: str, out_path: str, pw: Optional[str], verbose: bool=False) -> int:
    arr = load_img(img_path)
    pixels = arr.shape[0] * arr.shape[1]
    total_slots = pixels * CHANNELS * LSB_PER_CHANNEL
    flat = arr.reshape(-1, 3).astype(np.uint8).flatten()
    # read header bits sequentially
    header_bits_len = HEADER_LEN * 8
    header_bits = (flat[:header_bits_len] & 1).astype(np.uint8)
    header_bytes = bytes_from_bits(header_bits)
    try:
        m, enc_flag, s_len, n_len, ct_len = struct.unpack(HEADER_STRUCT, header_bytes)
    except Exception as e:
        raise ValueError("Invalid header or image not stego-packed") from e
    if m != MAGIC:
        raise ValueError("Invalid stego magic.")

    salt_bits_len = s_len * 8
    nonce_bits_len = n_len * 8
    salt_start = header_bits_len
    salt_end = salt_start + salt_bits_len
    nonce_end = salt_end + nonce_bits_len

    salt = bytes_from_bits((flat[salt_start:salt_end] & 1).astype(np.uint8)) if s_len else b""
    nonce = bytes_from_bits((flat[salt_end:nonce_end] & 1).astype(np.uint8)) if n_len else b""

    ct_bits_len = ct_len * 8
    ct_bits = extract_payload_bits_from_flat(flat, salt, nonce, nonce_end, ct_bits_len) if ct_bits_len else np.zeros(0, dtype=np.uint8)
    ciphertext = bytes_from_bits(ct_bits)

    if enc_flag:
        if not pw:
            raise ValueError("Payload is encrypted: provide password")
        plaintext = decrypt(ciphertext, salt, nonce, pw)
    else:
        plaintext = ciphertext

    if len(plaintext) < 4:
        raise ValueError("Invalid payload format: too short")
    filename_len = int.from_bytes(plaintext[:4], 'big')
    if len(plaintext) < 4 + filename_len:
        raise ValueError("Invalid payload format: filename length mismatch")
    filename_bytes = plaintext[4:4 + filename_len]
    data = plaintext[4 + filename_len:]
    filename = filename_bytes.decode()

    # Determine output path
    if os.path.isdir(out_path):
        final_path = os.path.join(out_path, filename)
    else:
        base = os.path.basename(out_path)
        if '.' not in base:
            _, ext = os.path.splitext(filename)
            if ext:
                out_path = out_path + ext
        final_path = out_path

    with open(final_path, "wb") as f:
        f.write(data)
    if verbose:
        print(f"[ok] Extracted {len(data)} bytes to '{final_path}'")
    return len(data)

# ---------------- GUI ----------------
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")
class StegoGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Hide and Extract Secrets — GUI Mode")
        self.geometry("1100x700")
        self.minsize(900,600)
        self._task_queue = queue.Queue()
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        # Sidebar frame
        self.sidebar = ctk.CTkFrame(self, width=320, corner_radius=10)
        self.sidebar.grid(row=0, column=0, padx=12, pady=12, sticky="ns")
        self.sidebar_visible = True
        # Main frame with tabs
        self.main = ctk.CTkFrame(self, corner_radius=10)
        self.main.grid(row=0, column=1, padx=12, pady=12, sticky="nsew")
        self.main.grid_rowconfigure(0, weight=1)
        self.main.grid_columnconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main()
        self.after(200, self._poll_queue)
    def _build_sidebar(self):
        self.sidebar.grid_rowconfigure((0,1,2,3,4,5,6,7,8,9,10,11), weight=0)
        self.sidebar.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.sidebar, text="Stego Controls", font=ctk.CTkFont(size=18,weight="bold")).grid(row=0, column=0, pady=(12,8))
        self.mode_var = ctk.StringVar(value="hide")
        ctk.CTkSegmentedButton(self.sidebar, values=["hide","extract"], variable=self.mode_var, command=self._on_mode_change).grid(row=1, column=0, pady=8)
        self.image_path_var = ctk.StringVar()
        self.secret_path_var = ctk.StringVar()
        self.output_path_var = ctk.StringVar()
        self.password_var = ctk.StringVar()
        self.verbose_var = ctk.BooleanVar(value=False)
        ctk.CTkButton(self.sidebar,text="Select Image",command=self._select_image).grid(row=2, column=0, padx=12, pady=(10,6), sticky="ew")
        self.image_label = ctk.CTkLabel(self.sidebar,textvariable=self.image_path_var,wraplength=240)
        self.image_label.grid(row=3, column=0, padx=12, sticky="w")
        self.secret_btn = ctk.CTkButton(self.sidebar,text="Select Secret File",command=self._select_secret)
        self.secret_btn.grid(row=4, column=0, padx=12, pady=(10,6), sticky="ew")
        self.secret_label = ctk.CTkLabel(self.sidebar,textvariable=self.secret_path_var,wraplength=240)
        self.secret_label.grid(row=5, column=0, padx=12, sticky="w")
        self.output_btn = ctk.CTkButton(self.sidebar,text="Select Output File",command=self._select_output)
        self.output_btn.grid(row=6, column=0, padx=12, pady=(10,6), sticky="ew")
        ctk.CTkLabel(self.sidebar,textvariable=self.output_path_var,wraplength=240).grid(row=7, column=0, padx=12, sticky="w")
        ctk.CTkLabel(self.sidebar, text="Password (optional):").grid(row=8, column=0, padx=12, pady=(12,0), sticky="w")
        ctk.CTkEntry(self.sidebar, textvariable=self.password_var).grid(row=9, column=0, padx=12, pady=(0,6), sticky="ew")
        self.progress_bar = ctk.CTkProgressBar(self.sidebar, width=200)
        self.progress_bar.grid(row=10, column=0, padx=12, pady=(6,6))
        self.progress_bar.set(0)
        self.action_btn = ctk.CTkButton(self.sidebar,text="Hide →",fg_color="#ff0000", hover_color="#cc0000", command=self._on_action)
        self.action_btn.grid(row=11, column=0, padx=12, pady=(14,6), sticky="ew")

    def _build_main(self):
        self.main.grid_columnconfigure(1, weight=1)
        self.main.grid_rowconfigure(1, weight=1)
        top = ctk.CTkFrame(self.main)
        top.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=12)
        top.grid_columnconfigure(1, weight=1)
        self.preview_label = ctk.CTkLabel(top, text="No image selected", width=220, height=160, corner_radius=8)
        self.preview_label.grid(row=0, column=0, rowspan=2, padx=(0,12))
        self.info_text = ctk.CTkLabel(top, text="Image info will appear here", anchor="w")
        self.info_text.grid(row=0, column=1, sticky="nw")
        self.capacity_text = ctk.CTkLabel(top, text="", anchor="w")
        self.capacity_text.grid(row=1, column=1, sticky="nw")
        self.log = ctk.CTkTextbox(self.main, width=-1, height=320)
        self.log.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=12, pady=(0,12))
        self.log.insert("0.0", "Ready.\n")
        self.log.configure(state="disabled")
        ctk.CTkButton(self.main, text="Clear Logs", command=self._clear_logs).grid(row=2, column=0, columnspan=2, padx=12, pady=(0,12))
    def _clear_logs(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.insert("0.0", "Logs cleared.\n")
        self.log.configure(state="disabled")
    def _log(self,line): self.log.configure(state="normal"); self.log.insert("end",line+"\n"); self.log.see("end"); self.log.configure(state="disabled")
    def _poll_queue(self):
        try:
            while True: self._log(self._task_queue.get_nowait())
        except queue.Empty: pass
        self.after(200,self._poll_queue)
    def _on_mode_change(self,value=None):
        mode = self.mode_var.get()
        self.action_btn.configure(text="Hide →" if mode=="hide" else "Extract →")
        # Clear input fields
        self.image_path_var.set("")
        self.secret_path_var.set("")
        self.output_path_var.set("")
        self.password_var.set("")
        # Clear preview
        self.preview_label.configure(image=None, text="No image selected")
        self.info_text.configure(text="Image info will appear here")
        self.capacity_text.configure(text="")
        if mode == "hide":
            self.secret_btn.grid()
            self.secret_label.grid()
        else:
            self.secret_btn.grid_remove()
            self.secret_label.grid_remove()
    def _select_image(self):
        p = filedialog.askopenfilename(title="Select image",filetypes=[("PNG/JPEG","*.png;*.jpg;*.jpeg"),("All files","*")])
        if p: self.image_path_var.set(p); self._update_preview(p)
    def _select_secret(self):
        p = filedialog.askopenfilename(title="Select secret file")
        if p: self.secret_path_var.set(p)
    def _select_output(self):
        mode = self.mode_var.get()
        if mode == "hide":
            p = filedialog.asksaveasfilename(title="Select output file",defaultextension=".png",filetypes=[("PNG","*.png")])
        else:  # extract
            p = filedialog.askdirectory(title="Select output folder")
            if p:
                # Set to folder path, will append filename later
                self.output_path_var.set(p)
        if p: self.output_path_var.set(p)
    def _update_preview(self,path):
        try:
            img = Image.open(path).convert("RGB"); img.thumbnail((320,240))
            self._preview_img = CTkImage(img, size=(220,160))
            self.preview_label.configure(image=self._preview_img,text="")
            w, h = img.size
            pixels = w * h
            capacity_bytes = (pixels * CHANNELS * LSB_PER_CHANNEL) // 8
            self.info_text.configure(text=f"{os.path.basename(path)} — {w}x{h}")
            self.capacity_text.configure(text=f"Capacity: {capacity_bytes} bytes")
        except Exception as e:
            self._log(f"[error] preview failed: {e}")
            self.capacity_text.configure(text="")
    def _on_action(self):
        mode = self.mode_var.get(); image = self.image_path_var.get(); secret = self.secret_path_var.get()
        output = self.output_path_var.get(); pw = self.password_var.get() or None; verbose = True
        if not image: messagebox.showerror("Error","Select an image first"); return
        if mode=='hide':
            if not output: messagebox.showerror("Error","Select an output path"); return
            if not secret: messagebox.showerror("Error","Select a secret file"); return
        elif mode=='extract':
            if not output:
                # Auto-generate output path for extract
                base_name = os.path.splitext(os.path.basename(image))[0]
                output = os.path.join(os.path.dirname(image), f"{base_name}_extracted.txt")
                self.output_path_var.set(output)
            elif os.path.isdir(output):
                # If output is a folder, append a default filename
                base_name = os.path.splitext(os.path.basename(image))[0]
                output = os.path.join(output, f"{base_name}_extracted")
        self.action_btn.configure(state="disabled")
        threading.Thread(target=self._worker_task,args=(mode,image,secret,output,pw,verbose),daemon=True).start()
    def _worker_task(self,mode,image,secret,output,pw,verbose):
        try:
            self.after(0, lambda: self.progress_bar.set(0.1))
            if mode=="hide":
                self._task_queue.put(f"[info] Hiding '{os.path.basename(secret)}' into '{os.path.basename(image)}'...")
                self.after(0, lambda: self.progress_bar.set(0.5))
                n = hide_secret(image,secret,output,pw,verbose)
                self.after(0, lambda: self.progress_bar.set(1.0))
                self._task_queue.put(f"[ok] Embedded {n} bytes into '{output}'")
            else:
                self._task_queue.put(f"[info] Extracting from '{os.path.basename(image)}' to '{output}'...")
                self.after(0, lambda: self.progress_bar.set(0.5))
                n = extract_secret(image,output,pw,verbose)
                self.after(0, lambda: self.progress_bar.set(1.0))
                self._task_queue.put(f"[ok] Extracted {n} bytes to '{output}'")
        except Exception as e:
            self._task_queue.put(f"[error] {e}")
            self.after(0, lambda: self.progress_bar.set(0))
        finally:
            self.after(0, lambda: self.action_btn.configure(state="normal"))
            self.after(2000, lambda: self.progress_bar.set(0))  # Reset after 2 seconds
def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Hide and Extract Secrets — CLI Mode")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    hide = sub.add_parser("hide")
    hide.add_argument("-i", "--image", required=True)
    hide.add_argument("-s", "--secret", required=True)
    hide.add_argument("-o", "--output", required=True)
    hide.add_argument("-p", "--password")

    extract = sub.add_parser("extract")
    extract.add_argument("-i", "--image", required=True)
    extract.add_argument("-o", "--output", required=True)
    extract.add_argument("-p", "--password")
    return p
def main():
    parser = build_argparser()
    args = parser.parse_args()
    try:
        if args.cmd == "hide":
            n = hide_secret(args.image, args.secret, args.output, args.password, verbose=args.verbose)
            print(f"[ok] Embedded {n} bytes into '{args.output}'")
        elif args.cmd == "extract":
            n = extract_secret(args.image, args.output, args.password, verbose=args.verbose)
            print(f"[ok] Extracted {n} bytes to '{args.output}'")
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        StegoGUI().mainloop()
    else:
        main()