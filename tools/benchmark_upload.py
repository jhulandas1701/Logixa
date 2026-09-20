import argparse,glob,os,time,requests

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dir",required=True);ap.add_argument("--url",default="http://localhost:8080/api/v1/ingest/files");ap.add_argument("--batch-size",type=int,default=50);a=ap.parse_args();files=sorted(glob.glob(os.path.join(a.dir,"*"))); 
    if not files:raise SystemExit("No files found")
    total=uploaded=0;start=time.perf_counter()
    for pos in range(0,len(files),a.batch_size):
        batch=files[pos:pos+a.batch_size]; handles=[]
        for p in batch: total+=os.path.getsize(p);handles.append(("files",(os.path.basename(p),open(p,"rb"),"application/octet-stream")))
        try:
            r=requests.post(a.url,files=handles,timeout=300);r.raise_for_status();uploaded+=len(r.json().get("uploaded_files",[]));print(f"Batch {pos+1}-{pos+len(batch)}: HTTP {r.status_code}")
        finally:
            for _,(_,f,_) in handles:f.close()
    elapsed=time.perf_counter()-start;mb=total/(1024*1024);print("\n=== LOGIXA INGESTION BENCHMARK ===");print(f"Files submitted : {len(files)}");print(f"Files accepted  : {uploaded}");print(f"Total data      : {mb:.2f} MB");print(f"Upload time     : {elapsed:.3f} s");print(f"Upload rate     : {mb/elapsed if elapsed else 0:.2f} MB/s")
if __name__=="__main__":main()
