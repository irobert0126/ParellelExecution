import os, sys, math, operator, time
import align, sysdig
import numpy as np

def diff_Length_Error():
    raise RuntimeWarning("The length of the two vectors are not the same!")

def list_to_npArray(vector1, vector2):
    '''convert the list to numpy array'''
    if type(vector1) == list:
        vector1 = np.array(vector1)
    if type(vector2) == list:
        vector2 = np.array(vector2)
    return vector1, vector2

def euclidean3(vector1, vector2):
    quar_distance = 0
    try:
        if(len(vector1) != len(vector2)):
            diff_Length_Error()
        zipVector = zip(vector1, vector2)
 
        for member in zipVector:
            quar_distance += (member[1] - member[0]) ** 2
 
        return quar_distance, math.sqrt(quar_distance)
 
    except Exception, err:
        sys.stderr.write('WARNING: %s\n' % str(err))
        return -1, -1
################################################################################
def grouping(profile):
  f_main_log = profile["main_log_fd"]
  profile["groups"] = []
  profile["groups"].append(sysdig.group_by_tid(profile["sysdig"][0]))
  profile["groups"].append(sysdig.group_by_tid(profile["sysdig"][1]))

  f_main_log.write("[+] Sysdig Log of Container (%s)\n" % profile["containers"][0].id)
  for group in profile["groups"]:
    for k,v in group.iteritems():
      fd = open(os.path.join(profile["conf"]["log"]["rootdir"], k), "w")
      fd.write("\n".join(v))
      fd.close()
      f_main_log.write("%s\t%s\n" % (k, " ".join(v)))
    f_main_log.write("\n\n")
  print "[+] #(%d) in group0 & #(%d) in group1" % (len(profile["groups"][0]), len(profile["groups"][1]))
  return profile

################################################################################
def dist_map_1(profile):
  f_main_log = profile["main_log_fd"]
  group1 = profile["groups"][0]
  group2 = profile["groups"][1]

  # Syscall to SetVector
  dict_map = {}
  group1_set = {}
  group2_set = {}
  for k,v in group1.iteritems():
    for i in set(v):
      if i not in dict_map:
        dict_map[i] = len(dict_map)
    group1_set[k] = {dict_map[i]:v.count(i) for i in set(v)}
  for k,v in group2.iteritems():
    for i in set(v):
      if i not in dict_map:
        dict_map[i] = len(dict_map)
    group2_set[k] = {dict_map[i]:v.count(i) for i in set(v)}

  for k,v in group1_set.iteritems():
    buckets = [0] * len(dict_map)
    for index,count in v.iteritems():
      buckets[index] = count
    group1_set[k] = buckets

  for k,v in group2_set.iteritems():
    buckets = [0] * len(dict_map)
    for index,count in v.iteritems():
      buckets[index] = count
    group2_set[k] = buckets

  # group1_set[k] = the syscall vector of TID=k   
  dist_mapping = {}
  for k2,v2 in group2_set.iteritems():
    dist_mapping[k2] = {"match":0, "exact":{}, "all":{}}
    for k1,v1 in group1_set.iteritems():
      dist = euclidean3(v1, v2)[0]
      if dist < 10:
         dist_mapping[k2]["match"] = 100
         dist_mapping[k2]["exact"][k1] = dist
      dist_mapping[k2]["all"][k1] = dist
  time.sleep(1)
  for k2, v2 in dist_mapping.iteritems():
    if len(v2["exact"]) > 0:
      f_main_log.write("[*] For Compromised TID = %s, Identical Control TID = {%s}\n"
        % (k2, " ".join(v2["exact"].keys())))
    else:
      v2["all"] = sorted(v2["all"].iteritems(), key=lambda (k,v):v)
  f_main_log.flush()
  time.sleep(4)
  return dist_mapping

def step2(dist_mapping, profile):
  f_main_log = profile["main_log_fd"]
  f_main_log.write("\n[*] Futher Investigate on the following TID:\n")
  
  for k2, v2 in dist_mapping.iteritems():
    if v2["match"] == 0:
      f_main_log.write("[*] Compromised TID (%s)\n\t%s\n" % (k2, profile["groups"][1][k2]))
      f_main_log.write("    with TID=%s and Dist=%s\n" % (v2["all"][0][0], v2["all"][0][1]))

  candidates = [[k2, v2["all"][0]] for k2, v2 in dist_mapping.iteritems() if v2["match"] == 0]
  sort_by_min_dist = sorted(candidates, key=lambda (x): x[1][1], reverse = True)
  f_main_log.write("\n\n")
  f_main_log.write("[*] TOP 3 TID Candidates are:\n\t")
  f_main_log.write("\n\t".join(["Mal_TID(%s) Clostest TID(%s) w/ Dist=%s" 
      % (p[0], p[1][0], p[1][1]) for p in sort_by_min_dist[:3]]))
  f_main_log.write("\n\n")
  return None

  for k2, v2 in dist_mapping.iteritems():
    if len(v2["exact"]) == 0:
      sort_dist = sorted(v2["all"].iteritems(), key=lambda (k,v):v)
      rtn = " ".join(["%s:%s" % (kk, vv) for kk, vv in sort_dist])
      f_main_log.write("[*] Compromised TID (%s)\n\tDistance [%s]\n" % (k2, rtn))
      if sort_dist[0][1] > 10000:
         continue
      try:
        f_main_log.write("(%s - %s)\n" % (k2,sort_dist[0][0]))
        f_main_log.write(" ".join(profile["groups"][1][k2])+"\n")
        f_main_log.write(" ".join(profile["groups"][0][sort_dist[0][0]])+"\n")
        enc1, enc2, v = align.align(profile["groups"][1][k2], profile["groups"][0][sort_dist[0][0]])
        score, encodeds = align.score(enc1, enc2, v)
        for encoded in encodeds[0:1]:
          alignment = v.decodeSequenceAlignment(encoded)
          print "(%s - %s)\n" % (k2,sort_dist[0][0])
          print alignment
          f_main_log.write("\tSimilarity:%s (%s - %s)\n" % (alignment.percentIdentity(),k2,sort_dist[0][0]))
          f_main_log.write(str(alignment))
          f_main_log.write("\n\n")
      except:
        break
