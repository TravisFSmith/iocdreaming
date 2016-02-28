import csv, pxssh, re
import createSTIX

LOGSTASH_CONFDIR = '/opt/logstash/'
CIF_HOST = '10.10.10.10'
CIF_USER = 'ssh_user'
CIF_PASS = 'ssh_pass'


def runCIFExport(s,otype):
		command = 'cif --otype ' + otype + ' --format csv' 
		s.sendline (command)
		s.prompt() 
		rawfile = open('otype_' + otype + '.csv', 'w')
		rawfile.write(s.before)
		rawfile.close()
		with open('otype_' + otype + '.csv', 'r') as fin:
			data = fin.read().splitlines(True)
		with open('otype_' + otype + '.csv', 'w') as fout:
			fout.writelines(data[1:])

def parseCSV(otype):
	with open('otype_' + otype + '.csv') as csvfile:
		es = getElasticSearchService()
		reader = csv.DictReader(csvfile)
		f = open(LOGSTASH_CONFDIR + 'malicious' + otype + '.yaml','w')
		observableList=[]
		providerList=[]
		reportTimeList=[]
		for row in reader:
			observable=''
			confidence=''
			tlp=''
			group=''
			description=''
			tags=''
			cc=''
			altid_tlp=''
			provider=''
			altid=''
			reporttime=''
			rdata=''
			asn=''
			#Store everything for future reference, but only using observable, provider, and reporttime
			for (k,v) in row.items():
				if k=="observable":
					observable=v
				if k=="confidence":
					confidence=v
				if k=="tlp":
					tlp=v
				if k=="group":
					group=v
				if k=="description":
					description=v
				if k=="tags":
					tags=v
				if k=="cc":
					cc=v
				if k=="altid_tlp":
					altid_tlp=v
				if k=="provider":
					provider=v
				if k=="altid":
					altid=v
				if k=="reporttime":
					reporttime=v
				if k=="rdata":
					rdata=v
				if k=="asn":
					asn=v
			observableList.append(observable)
			providerList.append(provider)
			reportTimeList.append(reporttime)
		uniq = []
		seen = set()
		i=0
		for x in observableList:
			if x not in seen:
				uniq.append(x)
				seen.add(x)
				if otype == 'MD5':
					#Write Logstash YAML
					f.write('\"' + x + '\": \"YES\"\n')
					#Write STIX for TARDIS
					createSTIX.md5(observableList[i],providerList[i],reportTimeList[i])
				elif otype == 'IPV4':
					if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',str(observableList[i])):
						#Write Logstash YAML
						f.write('\"' + x + '\": \"YES\"\n')
						#Write STIX for TARDIS
						createSTIX.ipv4(observableList[i],providerList[i],reportTimeList[i])
				elif otype == 'URL':
					if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',str(observableList[i])):
						#Write Logstash YAML
						f.write('\"' + x + '\": \"YES\"\n')
						#Write STIX for TARDIS
						createSTIX.url(observableList[i],providerList[i],reportTimeList[i])
				if otype == 'FQDN':
					if x.startswith('http'):
						x = x.replace('\\','/')
					if len(x) < 1016:
						#Write Logstash YAML
						f.write('\"' + x + '\": \"YES\"\n')
					if observableList[i].startswith('http'):
						#Write STIX for TARDIS
						createSTIX.fqdn(observableList[i],providerList[i],reportTimeList[i])
			i=i+1
		f.close() 

if __name__ == '__main__':
	s = pxssh.pxssh(timeout=300)
	if not s.login (CIF_HOST, CIF_USER, CIF_PASS):
		print("SSH session failed on login.")
		print(str(s))
	else:
		print("Exporting MD5 from CIF")
		runCIFExport(s,'md5')
		print("Parsing MD5 data")
		parseCSV('MD5')
		
		print("Exporting IPv4 from CIF")
		runCIFExport(s,'ipv4')
		print("Parsing IPv4 data")
		parseCSV('IPV4')
		
		print("Exporting IPv6 from CIF")
		runCIFExport(s,'ipv6')
		print("Parsing IPv6 data")
		parseIPv6()
		
		print("Exporting URL from CIF")
		runCIFExport(s,'url')
		print("Parsing URL data")
		parseCSV('URL')
		
		print("Exporting FQDN from CIF")
		runCIFExport(s,'fqdn')
		print("Parsing FQDN data")
		parseCSV('FQDN')
		s.logout()