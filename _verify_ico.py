from PIL import IcoImagePlugin

path = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\icons\icon.ico'
f = open(path, 'rb')
ico = IcoImagePlugin.IcoFile(f)

for size in (256, 32, 48, 16):
    img = ico.getimage(size)
    out = r'C:\Users\pc\Desktop\BlackRose\_icon_preview_%s.png' % size
    img.save(out)
    print('saved', out, img.size)

f.close()
print('OK')


