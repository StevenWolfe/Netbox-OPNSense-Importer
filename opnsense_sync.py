import requests
import urllib3
import ipaddress
from django.contrib.contenttypes.models import ContentType
from extras.scripts import Script, StringVar, BooleanVar
from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site, Interface, MACAddress
from ipam.models import IPAddress
from virtualization.models import VirtualMachine, VMInterface

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# MAC values OPNsense reports for interfaces that have no real hardware
# address (loopback, IPsec enc, pflog, WireGuard, ...). These are not
# unique per-interface, so they must never be used to match an incoming
# interface to an existing NetBox interface.
PLACEHOLDER_MACS = {None, '', '00:00:00:00:00:00'}

# Pseudo/virtual interface name prefixes. VLAN sub-interfaces and tunnel
# interfaces frequently inherit their parent interface's real MAC address
# (or share the same placeholder MAC as other pseudo-interfaces), so
# MAC-based matching is unreliable for these - always match by name instead.
# See issue #3.
PSEUDO_INTERFACE_PREFIXES = (
    'lo', 'enc', 'pflog', 'vlan', 'wg', 'ovpn', 'gif', 'gre', 'ipsec', 'tun', 'bridge',
)

class OPNsenseSyncScript(Script):
    class Meta:
        name = "OPNsense Sync"
        description = "Sync Interfaces, IPs, and ARP table from OPNsense to NetBox"
        commit_default = True

    Tunnel = None
    TunnelGroup = None
    TunnelTermination = None
    TunnelEncapsulation = None
    vpn_available = False

    opnsense_url = StringVar(
        description="OPNsense URL (e.g., https://192.168.1.1)",
        default="https://192.168.1.1"
    )
    api_key = StringVar(
        description="OPNsense API Key"
    )
    api_secret = StringVar(
        description="OPNsense API Secret"
    )
    device_name = StringVar(
        description="Name of the Firewall (Device or VM) in NetBox",
        default="OPNsense-Firewall"
    )
    is_virtual_machine = BooleanVar(
        description="Is this a Virtual Machine? (Uncheck if it is a physical Device)",
        default=True
    )
    site_slug = StringVar(
        description="Slug of the Site/Cluster where the firewall is located",
        default="lab"
    )
    verify_ssl = BooleanVar(
        description="Verify SSL Certificate",
        default=False
    )

    def run(self, data, commit):
        self.opnsense_url = data['opnsense_url']
        self.auth = (data['api_key'], data['api_secret'])
        self.verify = data['verify_ssl']
        self.device_name = data['device_name']
        self.is_vm = data['is_virtual_machine']
        self.site_slug = data['site_slug']
        
        self.import_vpn_models()

        self.sess = requests.Session()
        self.sess.auth = self.auth
        self.sess.verify = self.verify

        obj = self.sync_object()
        if not obj:
            return "Failed to find/create firewall object."

        interfaces = self.get_opnsense_interfaces()
        self.sync_interfaces(obj, interfaces)

        wg_clients = self.get_wireguard_clients()
        self.sync_wireguard(obj, wg_clients)

        arp_data = self.get_opnsense_arp()
        self.sync_arp_table(arp_data)

        return "Sync Complete"

    def import_vpn_models(self):
        try:
            from vpn.models import Tunnel, TunnelGroup, TunnelTermination
            self.Tunnel = Tunnel
            self.TunnelGroup = TunnelGroup
            self.TunnelTermination = TunnelTermination
            self.TunnelEncapsulation = None
            self.vpn_available = True
            self.log_success("VPN Models imported successfully (NetBox 4.0+ Core).")
        except ImportError:
            try:
                from netbox_vpn_plugin.models import Tunnel, TunnelGroup, TunnelTermination, TunnelEncapsulation
                self.Tunnel = Tunnel
                self.TunnelGroup = TunnelGroup
                self.TunnelTermination = TunnelTermination
                self.TunnelEncapsulation = TunnelEncapsulation
                self.vpn_available = True
                self.log_success("NetBox VPN Plugin models imported successfully.")
            except ImportError:
                self.vpn_available = False

    def _api_get_with_fallback(self, new_path, legacy_path, label):
        """
        OPNsense 25.7 ("Visionary Viper") re-registered its default ACLs against
        snake_case API URLs; the old camelCase URLs still route to the same
        controller action but are no longer reliably covered by narrow privilege
        grants (opnsense/core#9093, opnsense/core#7256). Try the current
        snake_case path first and fall back to the legacy camelCase path so this
        still works against pre-25.7 installs. Every non-200 is surfaced via
        log_warning so a future naming/permission regression shows up in the run
        log instead of silently producing empty data.
        """
        for path in (new_path, legacy_path):
            try:
                resp = self.sess.get(f"{self.opnsense_url}{path}")
            except Exception as e:
                self.log_warning(f"{label}: request to {path} failed: {e}")
                continue
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError as e:
                    self.log_warning(f"{label}: {path} returned non-JSON response: {e}")
                    return None
            self.log_warning(f"{label}: {path} returned HTTP {resp.status_code}")
        return None

    def _extract_ipv4_cidrs(self, ipv4_list):
        cidrs = []
        if not isinstance(ipv4_list, list):
            return cidrs
        for entry in ipv4_list:
            if isinstance(entry, str):
                cidrs.append(entry)
            elif isinstance(entry, dict):
                addr = entry.get('ipaddr') or entry.get('address')
                if not addr:
                    continue
                if '/' in addr:
                    cidrs.append(addr)
                elif 'subnetbits' in entry:
                    cidrs.append(f"{addr}/{entry['subnetbits']}")
                elif 'netmask' in entry:
                    try:
                        mask = entry['netmask']
                        if isinstance(mask, str) and mask.startswith('0x'):
                            mask = str(ipaddress.IPv4Address(int(mask, 16)))
                        prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                        cidrs.append(f"{addr}/{prefix_len}")
                    except Exception:
                        pass
        return cidrs

    def _get_interface_names_map(self):
        data = self._api_get_with_fallback(
            "/api/diagnostics/interface/get_interface_names",
            "/api/diagnostics/interface/getInterfaceNames",
            "Interface names",
        )
        if not isinstance(data, dict):
            self.log_warning("Could not retrieve interface name mapping; interface descriptions may be blank.")
            return {}
        return data

    def _get_interfaces_from_overview(self, names_map):
        """
        Preferred data source on OPNsense 23.1+: the same 'Interfaces > Overview'
        endpoint the admin GUI itself uses, gated by the narrow 'Status: Interfaces'
        privilege (api/interfaces/overview/*). Unlike getInterfaceConfig (see
        _get_interfaces_legacy), this endpoint has real ACL coverage without
        needing 'All Pages', and already returns MAC + IP data joined per interface.
        """
        data = self._api_get_with_fallback(
            "/api/interfaces/overview/interfaces_info",
            "/api/interfaces/overview/interfacesInfo",
            "Interfaces overview",
        )
        if not isinstance(data, dict) or not data.get('rows'):
            return None

        interfaces = []
        for row in data['rows']:
            device = row.get('device')
            if not device:
                continue
            interfaces.append({
                'device': device,
                'description': row.get('description') or names_map.get(device, device),
                'ipv4': self._extract_ipv4_cidrs(row.get('ipv4')),
                'macaddr': row.get('macaddr'),
            })
        return interfaces

    def _get_interfaces_legacy(self, names_map):
        """
        Fallback for OPNsense installs predating the Interfaces Overview API.
        Note: get_interface_config/getInterfaceConfig has no narrow ACL privilege
        pattern in stock OPNsense at all (confirmed against core's ACL.xml
        definitions) - it only works when the API user is granted 'All Pages'.
        """
        stats_data = self._api_get_with_fallback(
            "/api/diagnostics/interface/get_interface_statistics",
            "/api/diagnostics/interface/getInterfaceStatistics",
            "Interface statistics",
        )
        stats_map = stats_data.get('statistics', {}) if isinstance(stats_data, dict) else {}

        if not stats_map:
            self.log_info("Statistics map empty. Trying interface config (requires 'All Pages' privilege)...")
            config_data = self._api_get_with_fallback(
                "/api/diagnostics/interface/get_interface_config",
                "/api/diagnostics/interface/getInterfaceConfig",
                "Interface config",
            )
            if isinstance(config_data, dict) and 'rows' in config_data:
                stats_map = {row.get('identifier'): row for row in config_data['rows']}
            elif isinstance(config_data, dict):
                stats_map = config_data

        stats_by_device = {}
        for key, val in stats_map.items():
            if isinstance(val, dict):
                dev = val.get('device')
                if dev:
                    stats_by_device[dev] = val

        interfaces = []
        for name_key, name_val in names_map.items():
            phys_name = name_key
            descr = name_val

            prefixes = ['vtnet', 'em', 'igb', 'ix', 'vmx', 're', 'lo', 'enc', 'wg']
            is_val_phys = name_val in stats_by_device or any(name_val.startswith(p) for p in prefixes)
            is_key_phys = name_key in stats_by_device or any(name_key.startswith(p) for p in prefixes)

            if is_val_phys and not is_key_phys:
                phys_name = name_val
                descr = name_key

            iface_data = {
                'device': phys_name,
                'description': descr,
                'ipv4': [],
                'macaddr': None
            }

            stat = stats_by_device.get(phys_name)
            if not stat:
                candidates = [descr, descr.lower(), name_key, name_key.lower()]
                for cand in candidates:
                    if cand in stats_map:
                        stat = stats_map[cand]
                        break

            if stat:
                if 'macaddr' in stat:
                    iface_data['macaddr'] = stat['macaddr']
                elif 'ether' in stat:
                    iface_data['macaddr'] = stat['ether']

                iface_data['ipv4'].extend(self._extract_ipv4_cidrs(stat.get('ipv4')))
                iface_data['ipv4'].extend(self._extract_ipv4_cidrs(stat.get('inet')))
            else:
                self.log_info(f"No stats found for {phys_name} ({descr})")

            interfaces.append(iface_data)

        return interfaces

    def get_opnsense_interfaces(self):
        try:
            names_map = self._get_interface_names_map()

            interfaces = self._get_interfaces_from_overview(names_map)
            if interfaces is not None:
                self.log_success(f"Found {len(interfaces)} interfaces (via Interfaces Overview API).")
                return interfaces

            self.log_warning(
                "Interfaces Overview API unavailable; falling back to legacy Diagnostics "
                "interface endpoints."
            )
            interfaces = self._get_interfaces_legacy(names_map)
            self.log_success(f"Found {len(interfaces)} interfaces (via legacy Diagnostics API).")
            return interfaces

        except Exception as e:
            self.log_failure(f"Interface sync failed: {e}")
            return []

    def get_wireguard_clients(self):
        # api/wireguard/client/* and api/wireguard/server/* are wildcard ACL
        # patterns (verified in opnsense/core's Wireguard ACL.xml), so these
        # camelCase action names are unaffected by the 25.7 ACL rename and
        # don't need a snake_case fallback.
        try:
            resp = self.sess.get(f"{self.opnsense_url}/api/wireguard/client/searchClient")
            if resp.status_code == 200:
                return resp.json().get('rows', [])
            self.log_warning(f"WireGuard client search returned HTTP {resp.status_code}, trying server search...")
            resp = self.sess.get(f"{self.opnsense_url}/api/wireguard/server/searchServer")
            if resp.status_code == 200:
                return resp.json().get('rows', [])
            self.log_warning(f"WireGuard server search returned HTTP {resp.status_code}")
        except Exception as e:
            self.log_info(f"WireGuard sync skipped: {e}")
        return []

    def get_opnsense_arp(self):
        data = self._api_get_with_fallback(
            "/api/diagnostics/interface/get_arp",
            "/api/diagnostics/interface/getArp",
            "ARP table",
        )
        if data is None:
            self.log_failure("Error fetching ARP: both get_arp and getArp endpoints failed.")
            return []
        return data

    def sync_object(self):
        if self.is_vm:
            vm = VirtualMachine.objects.filter(name=self.device_name).first()
            if not vm:
                vm = VirtualMachine.objects.filter(name__iexact=self.device_name).first()
            
            if not vm:
                self.log_failure(f"Virtual Machine '{self.device_name}' not found!")
                return None
            self.log_success(f"Found Virtual Machine: {vm.name}")
            return vm
        else:
            device = Device.objects.filter(name=self.device_name).first()
            if not device:
                device = Device.objects.filter(name__iexact=self.device_name).first()

            if not device:
                self.log_info(f"Device {self.device_name} not found. Creating...")
                
                role = DeviceRole.objects.filter(slug="firewall").first()
                if not role:
                    role = DeviceRole.objects.create(name="Firewall", slug="firewall", color="ff0000")
                
                dtype = DeviceType.objects.filter(slug="opnsense-vm").first()
                if not dtype:
                    manufacturer = Manufacturer.objects.filter(slug="opnsense").first()
                    if not manufacturer:
                        manufacturer = Manufacturer.objects.create(name="OPNsense", slug="opnsense")
                    dtype = DeviceType.objects.create(
                        manufacturer=manufacturer, 
                        model="OPNsense VM", 
                        slug="opnsense-vm",
                        u_height=0
                    )
                    
                site = Site.objects.filter(slug=self.site_slug).first()
                if not site:
                    self.log_failure(f"Site '{self.site_slug}' not found!")
                    return None

                device = Device.objects.create(
                    name=self.device_name,
                    device_type=dtype,
                    role=role,
                    site=site,
                    status="active"
                )
            self.log_success(f"Found/Created Device: {device.name}")
            return device

    def sync_interfaces(self, nb_obj, opn_interfaces):
        self.log_info(f"Syncing {len(opn_interfaces)} interfaces...")
        
        if isinstance(nb_obj, VirtualMachine):
            InterfaceModel = VMInterface
            filter_kwargs = {'virtual_machine': nb_obj}
            assigned_object_type = ContentType.objects.get_for_model(VMInterface)
        else:
            InterfaceModel = Interface
            filter_kwargs = {'device': nb_obj}
            assigned_object_type = ContentType.objects.get_for_model(Interface)
        
        for iface in opn_interfaces:
            if_name = iface.get('device')
            if not if_name: continue
                
            if_descr = iface.get('description', '')
            mac_addr = iface.get('macaddr')
            if mac_addr and mac_addr.lower() in PLACEHOLDER_MACS:
                mac_addr = None

            is_pseudo = if_name.lower().startswith(PSEUDO_INTERFACE_PREFIXES)

            nb_iface = None

            # 1. Try to find by MAC Address first (skipped for pseudo/virtual
            # interfaces - see PSEUDO_INTERFACE_PREFIXES above)
            if mac_addr and not is_pseudo:
                try:
                    mac_obj = MACAddress.objects.filter(mac_address=mac_addr).first()
                    if mac_obj and mac_obj.assigned_object:
                        if isinstance(nb_obj, VirtualMachine) and isinstance(mac_obj.assigned_object, VMInterface):
                            if mac_obj.assigned_object.virtual_machine == nb_obj:
                                nb_iface = mac_obj.assigned_object
                        elif isinstance(nb_obj, Device) and isinstance(mac_obj.assigned_object, Interface):
                            if mac_obj.assigned_object.device == nb_obj:
                                nb_iface = mac_obj.assigned_object
                except Exception:
                    pass

            # 2. Try to find by Name
            if not nb_iface:
                nb_iface = InterfaceModel.objects.filter(name=if_name, **filter_kwargs).first()
            
            if not nb_iface:
                self.log_success(f"Creating interface {if_name}")
                nb_iface = InterfaceModel.objects.create(
                    name=if_name,
                    description=if_descr,
                    **filter_kwargs
                )
            else:
                if nb_iface.name != if_name:
                    self.log_info(f"Renaming interface {nb_iface.name} to {if_name} (matched by MAC)")
                    nb_iface.name = if_name
                
                if nb_iface.description != if_descr:
                    nb_iface.description = if_descr
                
                nb_iface.save()

            if mac_addr:
                try:
                    mac_obj, created = MACAddress.objects.update_or_create(
                        assigned_object_type=assigned_object_type,
                        assigned_object_id=nb_iface.pk,
                        defaults={'mac_address': mac_addr}
                    )
                    if created:
                        self.log_success(f"Assigned MAC {mac_addr} to {if_name}")
                except Exception as e:
                    self.log_failure(f"Error syncing MAC for {if_name}: {e}")

            ips_to_sync = []
            
            if iface.get('ipaddr') and iface.get('mask'):
                ips_to_sync.append(f"{iface.get('ipaddr')}/{iface.get('mask')}")
            
            ipv4_list = iface.get('ipv4', [])
            if isinstance(ipv4_list, list):
                for ip_info in ipv4_list:
                    if isinstance(ip_info, str): ips_to_sync.append(ip_info)
                    elif isinstance(ip_info, dict): 
                        ips_to_sync.append(f"{ip_info.get('ipaddr')}/{ip_info.get('mask')}")

            for cidr in ips_to_sync:
                self.sync_ip(nb_iface, cidr)

    def sync_wireguard(self, nb_obj, wg_clients):
        if not wg_clients: return
        self.log_info(f"Syncing {len(wg_clients)} WireGuard tunnels...")

        if isinstance(nb_obj, VirtualMachine):
            InterfaceModel = VMInterface
            filter_kwargs = {'virtual_machine': nb_obj}
        else:
            InterfaceModel = Interface
            filter_kwargs = {'device': nb_obj}

        tunnel_group = None
        encap_obj = None
        
        if self.vpn_available:
            tunnel_group, _ = self.TunnelGroup.objects.get_or_create(
                slug="wireguard",
                defaults={"name": "WireGuard"}
            )
            
            if self.TunnelEncapsulation:
                encap_obj, _ = self.TunnelEncapsulation.objects.get_or_create(
                    slug="wireguard",
                    defaults={"name": "WireGuard"}
                )

        for client in wg_clients:
            name = client.get('name', 'WG-Tunnel')
            tunnel_ip = client.get('tunneladdress') or client.get('tunnel_address', '')
            endpoint = client.get('serveraddress') or client.get('endpoint_address') or client.get('endpoint', '')
            
            if_name = f"wg-{name}"
            
            nb_iface = InterfaceModel.objects.filter(name=if_name, **filter_kwargs).first()
            if not nb_iface:
                self.log_success(f"Creating VPN interface {if_name}")
                nb_iface = InterfaceModel.objects.create(
                    name=if_name,
                    description=f"WireGuard: {name} ({endpoint})" if endpoint else f"WireGuard: {name}",
                    **filter_kwargs
                )
            
            if tunnel_ip:
                for ip in tunnel_ip.split(','):
                    self.sync_ip(nb_iface, ip.strip())

            if self.vpn_available and tunnel_group:
                tunnel_name = f"WG-{name}"
                tunnel = self.Tunnel.objects.filter(name=tunnel_name, group=tunnel_group).first()
                if not tunnel:
                    self.log_success(f"Creating Tunnel {tunnel_name}")
                    
                    tunnel_defaults = {
                        "group": tunnel_group,
                        "status": "active",
                        "description": f"WireGuard Tunnel to {name}"
                    }
                    
                    if self.TunnelEncapsulation:
                        tunnel_defaults["encapsulation"] = encap_obj
                    else:
                        tunnel_defaults["encapsulation"] = "wireguard"

                    tunnel = self.Tunnel.objects.create(
                        name=tunnel_name,
                        **tunnel_defaults
                    )
                
                term = self.TunnelTermination.objects.filter(tunnel=tunnel, role="peer").first()
                
                outside_ip_obj = None
                if endpoint:
                    try:
                        cidr = f"{endpoint}/32" if '/' not in endpoint else endpoint
                        outside_ip_obj = IPAddress.objects.filter(address=cidr).first()
                        if not outside_ip_obj:
                            self.log_success(f"Creating Outside IP {cidr}")
                            outside_ip_obj = IPAddress.objects.create(
                                address=cidr,
                                status="active",
                                description=f"WireGuard Endpoint for {name}"
                            )
                    except Exception as e:
                        self.log_failure(f"Error resolving outside IP {endpoint}: {e}")

                if not term:
                    if isinstance(nb_iface, Interface):
                        ct = ContentType.objects.get_for_model(Interface)
                    elif isinstance(nb_iface, VMInterface):
                        ct = ContentType.objects.get_for_model(VMInterface)
                    else:
                        continue

                    if self.TunnelTermination.objects.filter(termination_type=ct, termination_id=nb_iface.pk).exists():
                        continue

                    try:
                        term = self.TunnelTermination(
                            tunnel=tunnel,
                            role="peer",
                            termination_type=ct,
                            termination_id=nb_iface.pk
                        )
                        if outside_ip_obj and hasattr(term, 'outside_ip'):
                            term.outside_ip = outside_ip_obj
                        
                        term.save()
                        self.log_success(f"Terminated Tunnel {tunnel_name} on {if_name}")
                    except Exception as e:
                        self.log_failure(f"Failed to terminate tunnel: {e}")
                
                elif outside_ip_obj and hasattr(term, 'outside_ip') and term.outside_ip != outside_ip_obj:
                    try:
                        term.outside_ip = outside_ip_obj
                        term.save()
                        self.log_success(f"Updated Tunnel Termination outside IP to {outside_ip_obj.address}")
                    except Exception as e:
                        self.log_failure(f"Failed to update outside IP: {e}")

    def sync_ip(self, nb_iface, cidr):
        try:
            nb_ip = IPAddress.objects.filter(address=cidr).first()
            if not nb_ip:
                self.log_success(f"Creating IP {cidr}")
                nb_ip = IPAddress.objects.create(
                    address=cidr,
                    status="active",
                    assigned_object_type=None,
                    assigned_object_id=None
                )
                nb_ip.assigned_object = nb_iface
                nb_ip.save()
            elif nb_ip.assigned_object_id != nb_iface.id:
                self.log_info(f"Re-assigning IP {cidr} to {nb_iface.name}")
                nb_ip.assigned_object = nb_iface
                nb_ip.save()
        except Exception as e:
            self.log_failure(f"Error syncing IP {cidr}: {e}")

    def sync_arp_table(self, arp_data):
        self.log_info(f"Processing {len(arp_data)} ARP entries...")
        
        for entry in arp_data:
            mac = entry.get('mac')
            ip = entry.get('ip')
            
            if not mac or not ip: continue
            mac = mac.lower()
            
            mac_obj = MACAddress.objects.filter(mac_address=mac).first()
            target_iface = None
            
            if mac_obj and mac_obj.assigned_object:
                target_iface = mac_obj.assigned_object
            
            if target_iface:
                nb_ips = IPAddress.objects.filter(address__istartswith=f"{ip}/")
                
                for nb_ip in nb_ips:
                    if nb_ip.assigned_object_id != target_iface.id:
                        self.log_success(f"ARP Discovery: Assigning {nb_ip.address} to {target_iface.name}")
                        nb_ip.assigned_object = target_iface
                        nb_ip.save()
