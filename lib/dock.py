import docker, time
from io import BytesIO
from docker import APIClient

client = docker.from_env()
print client.version()
cli = APIClient(base_url='unix://var/run/docker.sock')
def get_current_time():
  return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

def cleanup():
  global client
  for cli in client.containers.list(all=True):
    try:
      cli.stop()
      cli.remove()
    except:
      pass

def findImageByTag(name, v="latest"):
  global client
  for image in client.images.list(all=True):
    if "%s:%s" % (name, v) in image.tags:
      return image
  return None

def buildImage(dockerfile, name, force=False):
  global cli
  global client
  if not force:
    image_id = findImageByTag(name)
    if image_id:
      print "[+] Find Existing Image (%s): %s" % (name, image_id)
      return image_id
  try:
    #logs = cli.build(path=dockerfile, rm=True, tag=name)
    logs = cli.build(path=dockerfile, tag=name)
    time.sleep(5)
    image_id = findImageByTag(name)
    print get_current_time(), "[+] Build Image:", image_id
    return image_id
  except docker.errors.APIError as e:
    print e
  return None

def runC(image, cmd="", ports={}):
  global client
  container = client.containers.run(image, ports=ports, detach=True)
  print get_current_time(), "[+] Create Container:", container
  return container

def test_tomcat():
  cleanup()
  profile = {
    "dockerfile":"/home/t/AutoRox/testbed/cve-2017-12617/",
    "tag":"tomcat_vul",
    "image":"",
    "ports":[
     {'8080/tcp': 8080},
     {'8080/tcp': 8081}
    ],
  }
  image_id = buildImage(profile["dockerfile"], profile["tag"])
  c1 = runC(image_id, ports=profile["ports"][0])
  c2 = runC(image_id, ports=profile["ports"][1])
  print client.containers.list()
  return [c1, c2]
