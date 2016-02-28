#!/usr/bin/env python
# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

"""
Description: Build a STIX Indicator document containing a File observable with
an associated hash.
"""

# python-cybox
from cybox.objects.file_object import File
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from cybox.core import Observables, Observable, Object, ObservableComposition
# python-stix
import stix.utils as utils
from stix.core import STIXPackage
from stix.indicator import Indicator
from stix.exploit_target import ExploitTarget, Vulnerability

from urlparse import urlparse
import os.path
import time

def md5(hash,provider,reporttime):
    vuln = Vulnerability()
    vuln.cve_id = "MD5-" + hash
    vuln.description = "maliciousMD5"
    et = ExploitTarget(title=provider + " observable")
    et.add_vulnerability(vuln) 
    # Create a CyboX File Object
    f = File()
    # This automatically detects that it's an MD5 hash based on the length
    f.add_hash(hash)
    
    # Create an Indicator with the File Hash Object created above.
    indicator = Indicator()
    indicator.title = "MD5-" + hash
    indicator.description = ("Malicious hash " + hash + " reported from " + provider)
    indicator.set_producer_identity(provider)
    indicator.set_produced_time(reporttime)

    
    # Add The File Object to the Indicator. This will promote the CybOX Object
    # to a CybOX Observable internally.
    
    indicator.add_observable(f)

    # Create a STIX Package
    stix_package = STIXPackage()
    
    stix_package.add(et)
    stix_package.add(indicator)
    
    # Print the XML!
    #print(stix_package.to_xml())
    f = open('/opt/TARDIS/Observables/MD5/' + hash + '.xml','w')
    f.write(stix_package.to_xml())
    f.close()

def ipv4(ip,provider,reporttime):
    vuln = Vulnerability()
    vuln.cve_id = "IPV4-" + str(ip)
    vuln.description = "maliciousIPV4"
    et = ExploitTarget(title=provider + " observable")
    et.add_vulnerability(vuln)
    
    addr = Address(address_value=str(ip), category=Address.CAT_IPV4) 
    addr.condition = "Equals"
    
     # Create an Indicator with the File Hash Object created above.
    indicator = Indicator()
    indicator.title = "IPV4-" + str(ip)
    indicator.description = ("Malicious IPV4 " + str(ip) + " reported from " + provider)
    indicator.set_producer_identity(provider)
    indicator.set_produced_time(reporttime)
    indicator.add_observable(addr)
    # Create a STIX Package
    stix_package = STIXPackage()
    
    stix_package.add(et)
    stix_package.add(indicator)
    
    # Print the XML!
    #print(stix_package.to_xml())
    f = open('/opt/TARDIS/Observables/IPV4/' + str(ip) + '.xml','w')
    f.write(stix_package.to_xml())
    f.close()

def url(ip,provider,reporttime):
    vuln = Vulnerability()
    vuln.cve_id = "IPV4-" + str(ip)
    vuln.description = "maliciousURL"
    et = ExploitTarget(title=provider + " observable")
    et.add_vulnerability(vuln)
    
    addr = Address(address_value=str(ip), category=Address.CAT_IPV4) 
    addr.condition = "Equals"
    
     # Create an Indicator with the File Hash Object created above.
    indicator = Indicator()
    indicator.title = "URL-" + str(ip)
    indicator.description = ("Malicious URL " + str(ip) + " reported from " + provider)
    indicator.set_producer_identity(provider)
    indicator.set_produced_time(reporttime)
    indicator.add_observable(addr)
    # Create a STIX Package
    stix_package = STIXPackage()
    
    stix_package.add(et)
    stix_package.add(indicator)
    
    # Print the XML!
    #print(stix_package.to_xml())
    f = open('/opt/TARDIS/Observables/URL/' + str(ip) + '.xml','w')
    f.write(stix_package.to_xml())
    f.close()

def fqdn(fqdn,provider,reporttime):
    currentTime = time.time()
    parsed_uri = urlparse( str(fqdn) )
    domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    if domain.startswith('https'):
        domain = domain[8:]
    else:
        domain = domain[7:]
    if domain.endswith('/'):
        domain = domain[:-1]


    vuln = Vulnerability()
    vuln.cve_id = "FQDN-" + str(domain) + '_' + str(currentTime)
    vuln.description = "maliciousIPV4"
    et = ExploitTarget(title=provider + " observable")
    et.add_vulnerability(vuln)
    
    url = URI()
    url.value = fqdn
    url.type_ =  URI.TYPE_URL
    url.condition = "Equals"
    
     # Create an Indicator with the File Hash Object created above.
    indicator = Indicator()
    indicator.title = "FQDN-" + str(fqdn)
    indicator.description = ("Malicious FQDN " + str(fqdn) + " reported from " + provider)
    indicator.set_producer_identity(provider)
    indicator.set_produced_time(reporttime)
    indicator.add_observable(url)
    # Create a STIX Package
    stix_package = STIXPackage()
    
    stix_package.add(et)
    stix_package.add(indicator)
    
    # Print the XML!
    #print(stix_package.to_xml())
    
    
    f = open('/opt/TARDIS/Observables/FQDN/' + str(domain) + '_' + str(currentTime) + '.xml','w')
    f.write(stix_package.to_xml())
    f.close()

    