"""Tar bort planritningarna som ligger inbäddade i netatlas.html när imagen byggs.

De är dina egna (privata) ritningar och ska inte följa med en image som kan delas med andra.
Ritningar du redan använder finns i ditt krypterade valv och påverkas inte."""
import re
import sys

path = sys.argv[1]
with open(path, encoding='utf-8') as f:
    html = f.read()
html, n = re.subn(r'<script id="housePlans" type="application/json">.*?</script>\n?', '', html, flags=re.S)
with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(html)
print(f'{path}: {n} inbäddade planritningsblock borttagna')
