"""Enable speed controls with all bandwidth limits initially disabled."""
import json
import pathlib
from tunnelscope.control import atomic_config

def main():
 p=pathlib.Path('/etc/tunnelscope/collector.json');config=json.loads(p.read_text())
 config.setdefault('speed_limits',{'enabled':False,'download_mbps':0,'upload_mbps':0,'clients':{},'state_file':'/var/lib/tunnelscope-policy/speed.json'})
 atomic_config(p,config)
 print('Speed controls ready; limits initially disabled; existing rules preserved')
if __name__=='__main__':main()
