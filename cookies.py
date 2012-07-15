#!/usr/bin/env python2
'''
usage: COMMAND FILE

the output format is:

    Server name
    (path , cookie_name , cookie_value , expiry , last_visited , secure , only_send_to_creator)

sorry, i didn't find that what is the version information using for....

'''
import sys
import struct

class cookie_records_data():
    def __init__(self,path_t):
        self.path=path_t
        self.name=''
        self.value=''
        self.expiry_date=0
        self.last_used_date=0
        self.unknow=''
        self.secure='FALSE' # 9BA9 anquan:fou jinfasong:shi A9 anquan:fou jinfasong:fou
        self.only_send='FALSE'

class cookie_domain_data:
    name=[]
    cookies=[]
    domain_level=-1

domain=[]
## du to the expiry_date
dic_fucker={}


#class cookie_domain(cookie_domain_data):
#    def getdomain_by_str():

def read_domains():
    domain_name_buf=[]
    domain_cookie_buf=[]
    domain_path_buf=[]
    
    tag_id=''
    while 1:
        tag_id=fp.read(1)
        if not tag_id:break

        if tag_id=='\x01':
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            domain_name_buf.append(read_record(str_len,''))

        elif tag_id=='\x02':
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            domain_path_buf.append(read_record(str_len,''))
        elif tag_id=='\x03':
            ##read cookie
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            domain_cookie_buf.append(read_record(str_len,domain_path_buf[:]))
        elif tag_id=='\x85':
            if domain_cookie_buf!=[]:
                domain_class=cookie_domain_data()
                domain_class.cookies=domain_cookie_buf
                domain_class.domain_level=''
                domain_class.name=domain_name_buf[:]
                domain_class.name.reverse()
                domain.append(domain_class)
                domain_path_buf=[]
                domain_cookie_buf=[]
        elif tag_id=='\x84':
            ##domain back
            if domain_name_buf!=[]:
                domain_name_buf.pop(-1)
        else:
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            read_record(str_len,'')

def read_record(len_f,path_t):
    cookies_class=cookie_records_data(path_t)
    while len_f>0:
        #print('len_fsssss='+str(len_f))
        domain_len=0
        tag_id=fp.read(1)
        len_f-=1
        
        if tag_id=='\x1E':
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            len_f-=2
            #print('sdfsdf',str_len)
            domain_name=fp.read(str_len)
            len_f-=str_len
            return domain_name
        elif tag_id=='\x10':
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            len_f-=2
            cookie_name=fp.read(str_len)
            len_f-=str_len
            cookies_class.name=cookie_name
            continue
        elif tag_id=='\x11':
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            len_f-=2
            cookie_value=fp.read(str_len)
            len_f-=str_len
            cookies_class.value=cookie_value
            continue
        elif tag_id=='\x12':
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            len_f-=2
            cookie_expiry=int("%d"%struct.unpack('>q',fp.read(str_len)))
            len_f-=str_len
            
            if cookie_expiry!=0:
                cookies_class.expiry_date=cookie_expiry
                dic_fucker[cookie_name]=cookie_expiry
            else:
                cookies_class.expiry_data=dic_fucker[cookie_name]
            continue
        elif tag_id=='\x13':
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            len_f-=2
            #print(cookie_name)
            cookie_last_used=int("%d"%struct.unpack('>q',fp.read(str_len)))
            len_f-=str_len
            cookies_class.last_used_date=cookie_last_used
            continue
        elif tag_id=='\x1D':
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            len_f-=2
            path=fp.read(str_len)
            len_f-=str_len
            return path
            
        elif tag_id=='\x28':
            str_len=int("%d"%struct.unpack('>H',fp.read(2))) #str length
            len_f-=2
            fp.read(str_len)
            len_f-=str_len
        elif tag_id=='\x99':              # MSB_VALUE(0x80) | 0x19
            cookies_class.secure='TRUE'
        elif tag_id=='\x9B':              # MSB_VALUE(0x80) | 0x1B
            cookies_class.only_send='TRUE'
    return cookies_class

def output_result():
    for i in domain:
        print('.'.join(i.name))
        for j in i.cookies:
            print(j.path,j.name,j.value,j.expiry_date,j.last_used_date,j.secure,j.only_send)

def to_netscape(tofile):
    filelines=[]
    for i in domain:
        for j in i.cookies:
            line='\t'.join([
            '.'.join(i.name),
            str(j.only_send),
            '/'+'/'.join(j.path),
            str(j.secure),
            str(j.expiry_date),
            str(j.name),
            str(j.value)
            ])
            filelines.append(line+'\n')
    fw=open(tofile,'w')
    fw.writelines(filelines)
    fw.close()

if __name__ == "__main__":
    if len(sys.argv)<=1:
        sfile=r'data/cookies4.dat'
        tofile=r'data/cookies.txt'
    else:
        sfile=sys.argv[1]
        tofile=sys.argv[2]
    fp=open(sfile,'rb')
    fp.seek(12)
    read_domains()
    #output_result()
    to_netscape(tofile)


