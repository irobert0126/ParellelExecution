import os, sys, subprocess, time

def get_current_time():
  return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

def load_sysdig_log(fpath):
  print "[+] load sysdig log (%s)", fpath
  return open(fpath, "r").readlines()

def parse_log(raw):
  print get_current_time(), "[+] Parsing (%d) lines of logs" % len(raw)
  p1_lines = []
  for line in raw:
    p1_lines.append(line.split(" "))
  return p1_lines

def group_by_tid(lines):
  groups = {}
  for line in lines:
    if len(line) < 6:
      print line
      continue
    if line[5] == ">":
      tid = line[4]
      if tid not in groups:
        groups[tid] = []
      groups[tid].append(line[6])
  return groups

def parse(fpath):
  return parse_log(load_sysdig_log(fpath))

def dump_syscall_name(p1_log):
  for p in p1_log:
    print p[0]
#========================================================
def record_container(cid=None, name=None, rootdir="./"):
  scap_path = os.path.join(rootdir, name+".scap")
  print get_current_time(), "[+] Start to record sysdig to (%s)" % scap_path
  if cid:
    pid = subprocess.Popen(["sudo", "sysdig", "-p'%evt.num|%evt.time|%evt.cpu|%proc.name|%thread.tid|%evt.dir|%evt.type|%evt.args'", "-qw", scap_path, "container.id=%s"%cid])
  else:
    pid = subprocess.Popen(["sudo", "sysdig", "-p'%evt.num|%evt.time|%evt.cpu|%proc.name|%thread.tid|%evt.dir|%evt.type|%evt.args'", "-qw", scap_path])
  return pid

def extract_log(dump, cid, rootdir="./"):
  dump_path = os.path.join(rootdir, dump)
  log_path = os.path.join(rootdir, cid)
  ignore_list = ["evt.type!=switch", "evt.type!=futex"]
  cmd = "sysdig -r %s %s > %s" % (dump_path, " and ".join(["container.id=%s" % cid, " and ".join(ignore_list)]), log_path)
  print "[+] Extracting log for container (%s) from (%s)" % (cid, dump_path)
  os.system(cmd)
  time.sleep(2)
  raw = open(log_path, "r").readlines()
  #os.remove(cid+".log")
  return raw

if __name__ == "__main__":
  extract_log("sha256:7d056fc512", "532ab60f0342")
