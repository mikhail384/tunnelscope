"""Add empty custom lists without replacing existing policies or exceptions."""
import json
import pathlib
from tunnelscope.control import atomic_config

def main():
 path=pathlib.Path('/etc/tunnelscope/collector.json');config=json.loads(path.read_text())
 config.setdefault('custom_policy',{'enabled':True,'domains':[],'client_domains':{},'exempt_client_ids':list(config.get('adult_policy',{}).get('exempt_client_ids',[]))})
 atomic_config(path,config)
 print('Custom lists ready; existing rules preserved')
if __name__=='__main__':main()
