import os
import sys
import json
import dateutil.parser
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import *


class Input(Script):
    MASK = "<encrypted>"
    APP = __file__.split(os.sep)[-3]

    def get_scheme(self):

        scheme = Scheme("Thinkst Canary Audit")
        scheme.description = ("Grab Audit data from the Thinkst Canary API")
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(Argument(
            name="domain",
            title="Domain",
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=False
        ))
        scheme.add_argument(Argument(
            name="auth_token",
            title="Auth Token",
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=False
        ))
        return scheme

    def stream_events(self, inputs, ew):
        self.service.namespace['app'] = self.APP
        # Get Variables
        input_name, input_items = inputs.inputs.popitem()
        kind, name = input_name.split("://")
        checkpointfile = os.path.join(self._input_definition.metadata["checkpoint_dir"], name)
        base = 'https://'+input_items["domain"]+'/api/v1/audit_trail/fetch'

        # Password Encryption
        updates = {}

        for item in ["auth_token"]:
            stored_password = [x for x in self.service.storage_passwords if x.username == item and x.realm == name]
            if input_items[item] == self.MASK:
                if len(stored_password) != 1:
                    ew.log(EventWriter.ERROR,f"Encrypted {item} was not found for {input_name}, reconfigure its value.")
                    return
                input_items[item] = stored_password[0].content.clear_password
            else:
                if(stored_password):
                    ew.log(EventWriter.DEBUG,"Removing Current password")
                    self.service.storage_passwords.delete(username=item,realm=name)
                ew.log(EventWriter.DEBUG,"Storing password and updating Input")
                self.service.storage_passwords.create(input_items[item],item,name)
                updates[item] = self.MASK
        if(updates):
            self.service.inputs.__getitem__((name,kind)).update(**updates)
        
        # Checkpoint
        try:
            lastid = int(open(checkpointfile, "r").read()) or 0
        except:
            ew.log(EventWriter.WARN,"No Checkpoint found")
            lastid = 0

        ew.log(EventWriter.INFO,f"Last ID is {lastid}")

        cursor = None
        count = 0
        params = {}

        with requests.Session() as session:
            session.headers.update({'Accept': 'application/json', 'X-Canary-Auth-Token': input_items["auth_token"]})
            while True:
                if(cursor):
                    params["cursor"] = cursor
                
                response = session.get(base, params=params)
                if(response.ok):
                    respdata = response.json()
                    events = respdata["audit_trail"]
                    if not cursor:
                        open(checkpointfile, "w").write(str(events[0]["id"]))
                    cursor = respdata["cursor"]["next"]
                    for event in events:
                        if event["id"] <= lastid:
                            cursor = None
                            break
                        ew.write_event(Event(
                            time=dateutil.parser.parse(event['timestamp']).timestamp(),
                            host=input_items["domain"],
                            source="/api/v1/audit_trail/fetch",
                            data=json.dumps(event, separators=(',', ':'))
                        ))
                        count += 1
                    
                    if not cursor:
                        break
                    
                else:
                    ew.log(EventWriter.ERROR,f"Request returned status {response.status_code}, {response.text}")
                    break
        ew.close()
        ew.log(EventWriter.INFO,f"Wrote {count} events")

if __name__ == '__main__':
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)