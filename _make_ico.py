import os
from PIL import Image

src = r'C:\Users\pc\Downloads\blackrose_logo.png'
dst = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\icons\icon.ico'

img = Image.open(src).convert('RGBA')
print('opened:', img.size, img.mode)

sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]

# Pillow's standard multi-size ICO save resizes internally to each size.
img.save(dst, format='ICO', sizes=sizes)

with open(dst, 'rb') as f:
    h = f.read(6)
print('ico size bytes =', os.path.getsize(dst))
print('header:', ' '.join(f'{b:02x}' for b in h), ' count =', h[4] | (h[5] << 8))

