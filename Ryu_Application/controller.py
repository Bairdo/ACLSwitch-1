# Copyright 2015 Jarrod N. Bakker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import signal
import os
import warnings
import sys

# Ryu and OpenFlow modules
from ryu.app.ofctl import api
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.controller import dpset
from ryu.controller.dpset import EventDPReconnected, EventDP

# Application modules
#from l2switch.l2switch import L2Switch
#from aclswitch.aclswitch import ACLSwitch
from authenticator.dot1xforwarder.dot1xforwarder import Dot1XForwarder
from authenticator.capflow.CapFlow import CapFlow

from faucet.faucet_copy import Faucet
from faucet.util import get_sys_prefix

#custom events
from faucet.faucet_events import EventFaucetReconfigure, EventFaucetResolveGateways, EventFaucetHostExpire
from authenticator.dot1xforwarder.dot1xforwarder import EventDot1xUserChange
from authenticator.capflow.CapFlow import EventCapFlowUserChange

# For dealing with the faucet config file
import ruamel.yaml as yaml
from ruamel.yaml.comments import CommentedMap
from threading import Lock

__author__ = "Jarrod N. Bakker"
__status__ = "Development"

class Controller(dpset.DPSet):
    """Abstracts the details of the Ryu controller.

    This class is used to provide applications with endpoints for
    modifying OpenFlow switches. Multiple Ryu applications can be
    instantiated from the controller class as a result.
    """

    #_CONTEXTS = {"wsgi": WSGIApplication}
    _EVENT_OFP_SW_FEATURES = ofp_event.EventOFPSwitchFeatures.__name__
    _EVENT_OFP_FLOW_REMOVED = ofp_event.EventOFPFlowRemoved.__name__
    _EVENT_OFP_PACKET_IN = ofp_event.EventOFPPacketIn.__name__
    _EVENT_OFP_PORT_STATUS = ofp_event.EventOFPPortStatus.__name__
    _EVENT_OFP_ERR = ofp_event.EventOFPErrorMsg.__name__
    
    _EVENT_FAUCET_RECONFIG = EventFaucetReconfigure.__name__
    _EVENT_FAUCET_RSLV_GW = EventFaucetResolveGateways.__name__
    _EVENT_FAUCET_HOST_EXP = EventFaucetHostExpire.__name__

    _EVENT_CAPFLOW_USR_CHANGE = EventCapFlowUserChange.__name__
    _EVENT_DOT1X_USR_CHANGE = EventDot1xUserChange.__name__
    
    _EVENT_DPSET_EV = dpset.EventDP.__name__
    _EVENT_DPSET_RECON = dpset.EventDPReconnected.__name__
    
    _SIGINT = signal.SIGINT
    
    _INSTANCE_NAME_CONTR = "ryu_controller_abstraction"

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self._apps = {}
        self._handlers = {self._EVENT_OFP_SW_FEATURES: [],
                          self._EVENT_OFP_FLOW_REMOVED: [],
                          self._EVENT_OFP_PACKET_IN: [],
                          self._EVENT_OFP_PORT_STATUS: [],
                          self._EVENT_OFP_ERR: [],                      
                          self._EVENT_FAUCET_RECONFIG: [],
                          self._EVENT_FAUCET_RSLV_GW: [], 
                          self._EVENT_FAUCET_HOST_EXP: [],
                          self._EVENT_CAPFLOW_USR_CHANGE: [],
                          self._EVENT_DOT1X_USR_CHANGE: [],
                          self._EVENT_DPSET_EV: [],
                          self._EVENT_DPSET_RECON: [],
                          self._SIGINT: [],
                          }
        #self._wsgi = kwargs['wsgi']
        
        #faucet file 
        self.faucet_config = os.getenv('FAUCET_CONFIG', get_sys_prefix() + '/etc/ryu/faucet/faucet.yaml')
        self.faucet_file_lock = Lock()
        
        # Insert Ryu applications below

        self._register_app(Dot1XForwarder(self))
        self._register_app(CapFlow(self))
        self._register_app(Faucet(self))
        
        signal.signal(signal.SIGHUP, self.signal_handler)
        signal.signal(signal.SIGUSR1, self.signal_handler)
        signal.signal(signal.SIGUSR2, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sigid, frame):
        """ Deal with received signals.
        
        :param sigid: The signal number
        :param frame: The current stack frame
        """
        if sigid == signal.SIGHUP:
			self.send_event('dpset', EventFaucetReconfigure())
        elif sigid == signal.SIGUSR1:
            self.send_event('dpset', EventDot1xUserChange())
        elif sigid == signal.SIGUSR2:
            self.send_event('dpset', EventCapFlowUserChange())
        elif sigid == signal.SIGINT:
            for app in self._handlers[self._SIGINT]:
                self._apps[app].clean_up()
            sys.exit(0)
        
		
    def get_ofpe_handlers(self):
        """Return the tuple of the OpenFlow protocol event handlers.

        :return: A tuple.
        """
        return self._handlers.keys()

    def register_rest_wsgi(self, rest_wsgi, **kwargs):
        """Register a WSGI with Ryu.

        :param rest_wsgi: The WSGI to register.
        :return: True is successful, False otherwise.
        """
        all_kwargs = kwargs["kwargs"].copy()
        all_kwargs[self._INSTANCE_NAME_CONTR] = self
        self._wsgi.register(rest_wsgi, all_kwargs)
        return True

    def _register_app(self, app_obj):
        """Register a Ryu app with the controller abstraction.

        :param app_obj: Reference to the app's Python module.
        """
        # Check that the Ryu app can be supported by the controller
        app_name = app_obj.get_app_name()
        if app_obj.is_supported() is True:
            self.logger.info("Registering Ryu app: %s", app_name)
            self._apps[app_name] = app_obj
        else:
            self.logger.error("Ryu app %s cannot be supported by the "
                              "controller.", app_name)
            return
        # Record what event handlers the Ryu app is listening for
        app_handlers = app_obj.get_expected_handlers()
        for handler in app_handlers:
            self._handlers[handler].append(app_name)

    # Methods that send data to OpenFlow switches

    def add_flow(self, datapath, priority, match, inst, hard_timeout,
                  table_id, buffer_id=None, in_port=None, msg=None, idle_timeout=0, packet_out=True, cookie=0):
        """Reactively add a flow table entry to a switch's flow table.

        :param datapath: The switch to add the flow-table entry to.
        :param priority: Priority of the flow-table entry.
        :param match: What packet header fields should be matched.
        :param inst: The behaviour that matching flows should follow.
        :param hard_timeout: When the rule should expire.
        :param table_id: What flow table the flow-table entry should
        be sent to.
        :param buffer_id: Identifier of buffer queue if traffic is
        being buffered.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    hard_timeout=0,
                                    idle_timeout=idle_timeout,
                                    priority=priority, match=match,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst, table_id=table_id, cookie=cookie)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    hard_timeout=0,
                                    idle_timeout=idle_timeout,
                                    priority=priority, match=match,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst, table_id=table_id, cookie=cookie)
        self._send_msg(datapath, mod)
        if packet_out:
            if msg:
                out = None
                if buffer_id and buffer_id != 0xffffffff:
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        actions=[parser.OFPActionOutput(ofproto.OFPP_TABLE)],
                        in_port=in_port,
                        buffer_id=buffer_id,
                        data=msg.data)
                    datapath.send_msg(out)
                else:
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        actions=[parser.OFPActionOutput(ofproto.OFPP_TABLE)],
                        in_port=in_port,
                        buffer_id=0xffffffff,
                        data=msg.data)
                    datapath.send_msg(out)

    def remove_flow(self, datapath, parser, table, remove_type, priority,
                    match, out_port, out_group, cookie=0, cookie_mask=0):
        """Remove a flow table entry from a switch.

        The callee should decide of the removal type.

        :param datapath: The switch to remove the flow from.
        :param parser: Parser for the OpenFlow switch.
        :param table: Table id to send the flow mod to.
        :param remove_type: OFPFC_DELETE or OFPFC_DELETE_STRICT.
        :param priority: Priority of the flow table entry.
        :param match: What packet header fields should be matched.
        :param out_port: Switch port to match.
        :param out_group: Switch group to match.
        """
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table,
                                command=remove_type, priority=priority,
                                match=match, out_port=out_port,
                                out_group=out_group,
                                cookie=cookie, cookie_mask=cookie_mask)
        datapath.send_msg(mod)

    def packet_out(self, datapath, out):
        """Send a packet out message to a switch.

        :param datapath: The switch to send the message to.
        :param out: The packet out message.
        """
        self._send_msg(datapath, out)

    def _send_msg(self, datapath, msg):
        """Send a message to a switch such as an OFPPacketOut message.

        :param datapath: The switch to send the message to.
        :param msg: The message to send to switch specified in datapath.
        """
        datapath.send_msg(msg)

    # Misc.
    def switch_get_datapath(self, datapath_id):
        """Return a datapath object given its datapath ID.

        :param datapath_id: ID of a datapath i.e. switch ID.
        :return: Datapath object.
        """
        return api.get_datapath(self, datapath_id)

    # OpenFlow switch event handlers

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, event):
        """Catch and handle OpenFlow Protocol SwitchFeatures events.

        :param event: The OpenFlow event.
        """
        
        datapath_id = event.msg.datapath_id

        self.logger.info("Switch \'{0}\' connected.".format(datapath_id))
        
        self.logger.info("Cleared rules in tables 0-10.")
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for table_id in range(0, 10):
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                    command=ofproto.OFPFC_DELETE, match=parser.OFPMatch())
        
        self._send_msg(datapath, mod)

        for app in self._handlers[self._EVENT_OFP_SW_FEATURES]:
            self._apps[app].switch_features(event)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    def _flow_removed_handler(self, event):
        """Catch and handle OpenFlow Protocol FlowRemoved events.

        :param event: The OpenFlow event.
        """
        msg = event.msg
        match = msg.match
        self.logger.info("Flow table entry removed.\n\t Flow match: {"
                         "0}".format(match))
        self.logger.info("Cookie: %x", msg.cookie)
    
	@set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
	def _port_status_handler(self, event):
		for app in self._handlers[self._EVENT_OFP_PORT_STATUS]:
			self._apps[app].port_status_handler(event)
            
                         
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, event):
        """Catch and handle OpenFlow Protocol PacketIn events.

        :param event: The OpenFlow event.
        """
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if event.msg.msg_len < event.msg.total_len:
            self.logger.warning("Packet truncated: only {0} of {1} "
                                "bytes".format(event.msg.msg_len,
                                               event.msg.total_len))
        for app in self._handlers[self._EVENT_OFP_PACKET_IN]:
            self._apps[app].packet_in(event)
            
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg

        self.logger.warning('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s',
                          msg.type, msg.code, msg.data)
        
        for app in self._handlers[self._EVENT_OFP_ERR]:
            self._apps[app]._error_handler(ev)
    
    # Faucet events
    
    @set_ev_cls(EventFaucetReconfigure, MAIN_DISPATCHER)
    def _reload_config(self, ev):
        """Handle Faucet Reconfigure events and alert the apps registered for it
        
        :param event: The Faucet event
        """
        for app in self._handlers[self._EVENT_FAUCET_RECONFIG]:
            self._apps[app].reload_config(ev)

    @set_ev_cls(EventFaucetResolveGateways, MAIN_DISPATCHER)
    def resolve_gateways(self, ev):
        """Handle Faucet Resolve Gateways events and alert the apps registered for it
        
        :param event: The Faucet event
        """
        for app in self._handlers[self._EVENT_FAUCET_RSLV_GW]:
            self._apps[app].resolve_gateways(ev)
        
    @set_ev_cls(EventFaucetHostExpire, MAIN_DISPATCHER)
    def host_expire(self, ev):
        """Handle Faucet Host Expire events and alert the apps registered for it
        
        :param event: The Faucet event
        """
        for app in self._handlers[self._EVENT_FAUCET_HOST_EXP]:
            self._apps[app].host_expire(ev)
    
    #Other events
    @set_ev_cls(EventDot1xUserChange, MAIN_DISPATCHER)
    def dot1x_user_change(self, ev):
        """Handle Dot1xUserChange events and alert the apps registered for it
        
        :param event: The Dot1x event
        """
        for app in self._handlers[self._EVENT_DOT1X_USR_CHANGE]:
            self._apps[app].reload_config(ev) 
            
    @set_ev_cls(EventCapFlowUserChange, MAIN_DISPATCHER)
    def capflow_user_change(self, ev):
        """Handle CapFlowUserChange events and alert the apps registered for it
        
        :param event: The Dot1x event
        """
        for app in self._handlers[self._EVENT_CAPFLOW_USR_CHANGE]:
            self._apps[app].reload_config(ev)        
            
    def _register(self,dp):
        '''
        A modification of dpset.DPSet._register(), where it generates events 
        when a datapath connects. Instead just calls functions of the registered apps
        '''
        self.logger.debug('DPSET: register datapath %s', dp)
        assert dp.id is not None

        # while dpid should be unique, we need to handle duplicates here
        # because it's entirely possible for a switch to reconnect us
        # before we notice the drop of the previous connection.
        # in that case,
        # - forget the older connection as it likely will disappear soon
        # - do not send EventDP leave/enter events
        # - keep the PortState for the dpid
        send_dp_reconnected = False
        if dp.id in self.dps:
            self.logger.warning('DPSET: Multiple connections from %s',
                                dpid_to_str(dp.id))
            self.logger.debug('DPSET: Forgetting datapath %s', self.dps[dp.id])
            (self.dps[dp.id]).close()
            self.logger.debug('DPSET: New datapath %s', dp)
            send_dp_reconnected = True
        self.dps[dp.id] = dp
        if dp.id not in self.port_state:
            self.port_state[dp.id] = dpset.PortState()
            ev = EventDP(dp, True)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                for port in dp.ports.values():
                    self._port_added(dp, port)
                    ev.ports.append(port)
            for app in self._handlers[self._EVENT_DPSET_EV]:
                self._apps[app].handler_connect_or_disconnect(ev)
        if send_dp_reconnected:
            ev = dpset.EventDPReconnected(dp)
            ev.ports = self.port_state.get(dp.id, {}).values()
            for app in self._handlers[self._EVENT_DPSET_RECON]:
                self._apps[app].handler_reconnect(ev)
    
    
    # Methods to add acl rules to the faucet config file
    
    def _load_faucet_config_file(self):
        """ Load the faucet config file into an ordered dict
        
        :return: the yaml file represented in an ordered dict
        """
        with open(self.faucet_config, "r") as f:
            return yaml.load(f, 
                             yaml.RoundTripLoader,
                             preserve_quotes=True)

    def _write_to_faucet_config_file(self, data):
        """ Overwrite the config file
        
        :param data: The data to overwrite the config file with
        """
        with open(self.faucet_config, "w") as f:
            yaml.dump(data,
                      f, 
                      Dumper=yaml.RoundTripDumper, 
                      indent=4,
                      block_seq_indent=2,
                      explicit_start=True)
    
    def duplicated(self, data, acl_key, rule):
        """ Check if a rule has been duplicated in the same group
        
        :param acl_key: The acl group number
        :param rule: The rule to be checked for duplicity
        
        """
        for entry in data["acls"][acl_key]:
            if entry["rule"] == rule:
                return True
        return False
    
    def add_acl_rule(self,acl_key, acl_rules):
        """ Add an acl rule to the faucet config file
        :param acl_key: The acl group number
        :param acl_rules: A list of OFPMatches and whether or not the match is allowed
        """
        with self.faucet_file_lock:
            data = self._load_faucet_config_file()
            
            for match, allow in acl_rules.iteritems():
                rule = CommentedMap()
                allow_rule = CommentedMap()
                allow_rule.insert(0, "allow", int(allow))
                rule.insert(0, "actions", allow_rule)

                for field, value in match.iteritems():
                    rule.insert(0, field, value)                
                
                if not self.duplicated(data, acl_key, rule):
                    final_rule = CommentedMap()
                    final_rule.insert(0, "rule", rule)
                    data["acls"][acl_key].insert(0, final_rule)
            
            self._write_to_faucet_config_file(data)
