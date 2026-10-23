"""Add application controls, initially disabled and without selected applications."""
import json
import pathlib
from tunnelscope.control import atomic_config
from tunnelscope.apps import catalog

def main():
 catalog();p=pathlib.Path('/etc/tunnelscope/collector.json');config=json.loads(p.read_text())
 config.setdefault('apps_policy',{'enabled':False,'app_ids':[],'clients':{},'exempt_client_ids':list(config.get('custom_policy',{}).get('exempt_client_ids',[])),'state_file':'/var/lib/tunnelscope-policy/apps.json'})
 atomic_config(p,config);print('Application controls ready; new rules initially disabled')
if __name__=='__main__':main()
