import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need
# fine tuning.
buildOptions = dict(packages=[
    'scapy',
    'scapy.layers'
], excludes=[])
base = ('Win32GUI' if sys.platform == 'win32' else None)

executables = [
    Executable('main.py', base=base, targetName='wireshrimp')
]

setup(
    name='Wireshrimp',
    version='1.0.0',
    description='A super simple Python based packet sniffer',
    options=dict(build_exe=buildOptions),
    executables=executables
)
