import argparse,json
from pathlib import Path

def cisco(i):
    return f"<134>Sep 04 20:31:{i%60:02d} FW01 %ASA-6-302013: Built outbound TCP connection {10000+i} for outside: 10.10.{i%250}.{i%250+1}/443 to 172.16.{i%250}.{(i*7)%250+1}/52341\n"
def forti(i):
    return f'date=2026-09-04 time=20:32:{i%60:02d} devname="FGT-01" type="traffic" srcip=192.168.{i%250}.{i%250+1} dstip=172.20.{i%250}.{(i*11)%250+1} srcport={40000+i%20000} dstport=443 proto=6 action="accept"\n'
def suri(i):
    return json.dumps({"timestamp":f"2026-09-04T20:33:{i%60:02d}.123Z","event_type":"alert","src_ip":f"10.0.{i%250}.{(i*13)%250+1}","dest_ip":"8.8.8.8","src_port":42000+i%1000,"dest_port":53,"proto":"UDP","alert":{"signature":"Possible DNS tunneling","severity":2}})+"\n"
def gxfw(i):
    return f"GXFW|20260904|2034{i%60:02d}|EDGE-{i%10:02d}|IN=eth0|OUT=wan0|SRC=172.16.{i%250}.{(i*17)%250+1}|DST=45.33.{i%250}.{(i*19)%250+1}|SP={49000+i%1000}|DP=443|P=TCP|DEC={'PASS' if i%2 else 'DROP'}|RSN=POL-{i%30:02d}\n"

# --- newly detectable known sources -----------------------------------

def apache(i):
    status = 200 if i % 5 else 404
    return (
        f'192.168.{i%250}.{i%250+1} - user{i%20} [04/Sep/2026:20:35:{i%60:02d} +0530] '
        f'"GET /index{i%10}.html HTTP/1.1" {status} {1200+i} '
        f'"https://example.com/ref{i%5}" "Mozilla/5.0 (compatible; LogixaBench/1.0)"\n'
    )

def nginx(i):
    status = 200 if i % 7 else 502
    return (
        f'10.0.{i%250}.{i%250+1} - - [04/Sep/2026:20:36:{i%60:02d} +0000] '
        f'"POST /api/v1/checkout HTTP/1.1" {status} {300+i} '
        f'"-" "curl/8.4.{i%10}"\n'
    )

def linux_auth(i):
    if i % 2:
        return (
            f"Sep  4 20:37:{i%60:02d} web-{i%5:02d} sshd[{20000+i}]: "
            f"Failed password for admin from 203.0.113.{i%250} port {50000+i%10000} ssh2\n"
        )
    return (
        f"Sep  4 20:37:{i%60:02d} web-{i%5:02d} sshd[{20000+i}]: "
        f"Accepted publickey for deploy from 198.51.100.{i%250} port {50000+i%10000} ssh2\n"
    )

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--count",type=int,default=100);ap.add_argument("--out",default="testdata/100");a=ap.parse_args();out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
    fs=[cisco,forti,suri,gxfw,apache,nginx,linux_auth]
    for i in range(1,a.count+1):
        f=fs[(i-1)%len(fs)]; ext=".json" if f is suri else ".log"; (out/f"{f.__name__}_{i:05d}{ext}").write_text(f(i))
    print(f"Generated {a.count} files in {out}")
if __name__=="__main__":main()
