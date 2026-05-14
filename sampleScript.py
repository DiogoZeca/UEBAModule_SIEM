import pandas as pd
import numpy as np
import ipaddress
import dns.resolver
import dns.reversename
import geoip2.database
import matplotlib.pyplot as plt 

#datafile='internal_train0.parquet'
datafile='internal_train0.json'

### IP geolocalization
geodb_path='./dbip-country-lite-2026-05.mmdb'
geodb=geoip2.database.Reader(geodb_path)

geodbasn_path='./dbip-asn-lite-2026-05.mmdb'
geodbasn=geoip2.database.Reader(geodbasn_path)


addr='193.136.173.21'
cc=geodb.country(addr).country.iso_code
cname=geodb.country(addr).country.names['en'] 
org=geodbasn.asn(addr).autonomous_system_organization
print(cc,cname,org)

# ### DNS resolution
# addr=dns.resolver.resolve("www.ua.pt", 'A')
# for a in addr:
    # print(a)
    
# ### Reverse DNS resolution    
# name=dns.reversename.from_address("193.136.172.20")
# addr=dns.resolver.resolve(name, 'PTR')
# for a in addr:
    # print(a)

### Read JSON data files
data=pd.read_json(datafile)
print(data)
#print(data.to_string())

#Just the UDP flows
udpF=data.loc[data['proto']=='udp']

#Number of UDP flows for each source IP
nudpF=data.loc[data['proto']=='udp'].groupby(['src_ip'])['up_bytes'].count()

#Number of UDP flows to port 443, for each source IP
nudpF443=data.loc[(data['proto']=='udp')&(data['port']==443)].groupby(['src_ip'])['up_bytes'].count()

#Average number of downloaded bytes, per flow, for each source IP
avgUp=data.groupby(['src_ip'])['down_bytes'].mean()
print(avgUp)

#Total uploaded bytes to destination port 443, for each source IP, ordered from larger amount to lowest amount
upS=data.loc[((data['port']==443))].groupby(['src_ip'])['up_bytes'].sum().sort_values(ascending=False)


#Upload/Download bytes ratio (traffic for port 443) for each source IP
a1=data.loc[((data['port']==443))].groupby(['src_ip'])['up_bytes'].sum()
a2=data.loc[((data['port']==443))].groupby(['src_ip'])['down_bytes'].sum()
a3=pd.DataFrame(a2/a1,columns=['ratio'])
a4=pd.concat([a1,a2,a3],axis=1).sort_values(by='ratio')
avgRatio=(a2/a1).mean()
stdRatio=(a2/a1).std()

print(a3.sort_values(by='ratio'))
print(avgRatio,stdRatio)

#Is destination IPv4 a public address?
NET=ipaddress.IPv4Network('192.168.0.0/16')
data['dst_public']=bpublic=data.apply(lambda x: ipaddress.IPv4Address(x['dst_ip']) not in NET,axis=1)

#Geolocalization of public destination adddress
data['dst_cc']=data[bpublic]['dst_ip'].apply(lambda y:geodb.country(y).country.iso_code).to_frame(name='cc')
print(data)

#Average interval between flows from same source IP (for each source IP)
data['diff_timestamp']=data.groupby(['src_ip'])['timestamp'].diff().fillna(0)
aibf=data.groupby(['src_ip'])['diff_timestamp'].mean().sort_values(ascending=False)
print(aibf)

#Histogram of the total uploaded bytes to destination port 443, by source IP
upS=data.loc[((data['port']==443))].groupby(['src_ip'])['up_bytes'].sum().hist()
plt.show()
