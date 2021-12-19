import os
import subprocess
import glob
import datetime

ver = subprocess.run("git describe --tags", shell=True, capture_output=True)
ver = ver.stdout.decode().strip()

full_ver = subprocess.run("git describe --always --dirty --long --tags", shell=True, capture_output=True)
full_ver = full_ver.stdout.decode().strip()

cur = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

t = [['linux', 'amd64'],
     ['linux', 'arm'],
     ['linux', 'arm64'],
     ['linux', 'mips'],
     ['linux', 'mipsle'],
     ['windows', 'amd64'],
]

# add -X 'network-measure/tool.speedUA=custom' in -ldflags to customize speed test client user-agent

for o, a in t:
    subprocess.run(
        f'''SET GOOS={o}&&SET GOARCH={a}&&'''
        f'''go build -tags="jsoniter" -ldflags="-s -w '''
        f'''-X main.fullVersion={full_ver} -X \'main.buildDate={cur}\'" '''
        f'''-o network-measure-http_{o}_{a}{".exe" if o == "windows" else ""} '''
        f'''../exec/http''', shell=True
    )
    subprocess.run(
        f'''SET GOOS={o}&&SET GOARCH={a}&&'''
        f'''go build -tags="jsoniter" -ldflags="-s -w '''
        f'''-X main.version={ver} -X main.fullVersion={full_ver} -X \'main.buildDate={cur}\'" '''
        f'''-o network-measure-ws_{o}_{a}{".exe" if o == "windows" else ""} '''
        f'''../exec/ws''', shell=True
    )

subprocess.run(
    f'''SET GOOS={o}&&SET GOARCH={a}&&'''
    f'''go build -tags="jsoniter" -ldflags="-s -w -H windowsgui '''
    f'''-X main.fullVersion={full_ver} -X \'main.buildDate={cur}\'" '''
    f'''-o network-measure-http_windowsgui_amd64.exe '''
    f'''../exec/http''', shell=True
)
subprocess.run(
    f'''SET GOOS={o}&&SET GOARCH={a}&&'''
    f'''go build -tags="jsoniter" -ldflags="-s -w -H windowsgui '''
    f'''-X main.version={ver} -X main.fullVersion={full_ver} -X \'main.buildDate={cur}\'" '''
    f'''-o network-measure-ws_windowsgui_amd64.exe '''
    f'''../exec/ws''', shell=True
)
