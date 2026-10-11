"""Local comparison against the frozen previous public implementation."""
import hashlib,importlib.util,json,platform,statistics,time
from pathlib import Path
from triage import analyze

ROOT=Path(__file__).resolve().parent

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def run():
    path=ROOT/'benchmarks/baseline_triage.py'
    spec=importlib.util.spec_from_file_location('frozen_baseline',path);baseline=importlib.util.module_from_spec(spec);spec.loader.exec_module(baseline)
    rows=[]
    for size in (1000,3000,6000):
        events = [{'id':str(i),'timestamp':'2026-01-01T00:00:00Z','kind':'login_failed','user':'synthetic','source_ip':'example'} for i in range(size)]
        inputs=(events,)
        kwargs={'failure_threshold':size+1,'window_seconds':300}
        expected=baseline.analyze(*inputs,**kwargs)
        actual=analyze(*inputs,**kwargs)
        if expected!=actual:raise ValueError('Output changed for synthetic timing fixture')
        timings={'baseline':[],'candidate':[]}
        for repeat in range(3):
            order=[('baseline',baseline.analyze),('candidate',analyze)]
            if repeat%2:order.reverse()
            for name,call in order:
                start=time.perf_counter();call(*inputs,**kwargs);timings[name].append(time.perf_counter()-start)
        rows.append({'size':size,'output_equivalent':True,'seconds':timings,'median_seconds':{name:statistics.median(samples) for name,samples in timings.items()}})
    return {'source_sha256':{'triage.py':sha(ROOT/'triage.py'),'baseline':sha(path),'benchmark':sha(Path(__file__))},'python':platform.python_version(),'machine':platform.machine(),'rows':rows,'scope':'Synthetic expiry-window timing with alerts suppressed. No production detection or end-to-end SOC throughput claim; emitting large evidence sets can still cost quadratic work.'}

if __name__=='__main__':print(json.dumps(run(),indent=2))
