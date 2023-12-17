import ssl
import json
import socket
import OpenSSL
import certifi #pip install certifi
from datetime import datetime ,  timedelta
from hello_tls import scan_server,ConnectionSettings #pip install hello-tls
from ocspchecker import ocspchecker #pip install ocsp-checker

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509 import load_pem_x509_certificate

with open("ciphers.json", 'r') as f:
    CIPHERS_RANKING = json.load(f)


def get_certificate_info(hostname):
    host_ip = socket.gethostbyname(hostname)
    cert = ssl.get_server_certificate((hostname,443))
    cert2 = ssl.get_server_certificate((host_ip,443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

    cert_info = {}
    cert_info['subject'] = {i.decode(): dict(x509.get_subject().get_components())[i].decode() for i in dict(x509.get_subject().get_components())}
    cert_info['issuer'] = {i.decode(): dict(x509.get_issuer().get_components())[i].decode() for i in dict(x509.get_issuer().get_components())}
    cert_info['serial_number'] = hex(x509.get_serial_number())[2:]
    cert_info['signature_algorithm'] = x509.get_signature_algorithm().decode()
    cert_info['public_key'] = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, x509.get_pubkey()).decode()
    cert_info['version'] = x509.get_version()
    cert_info['not_before'] = datetime.strptime(x509.get_notBefore().decode(), '%Y%m%d%H%M%SZ')+ timedelta(hours=8)
    cert_info['not_after'] = datetime.strptime(x509.get_notAfter().decode(),'%Y%m%d%H%M%SZ')+ timedelta(hours=8)
    cert_info['has_expired'] = x509.has_expired()
    extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
    extension_data = {e.get_short_name().decode(): str(e) for e in extensions}
    cert_info['subject_alt_name'] = extension_data['subjectAltName'].replace("DNS:","")
    ocsp_status, ocsp_origin = get_ocsp(hostname,cert)
    cert_info['ocsp_status'] = ocsp_status
    cert_info['ocsp_origin'] = ocsp_origin
    crl_list = get_crls(cert_info)
    cert_info['revoked'] = is_in_crl(cert_info['serial_number'], crl_list)
    cert_info['sha256_fingerprint'] = x509.digest('sha256').decode().replace(':','')
    

    return (cert_info,x509,cert)
def get_ocsp_server(cert):
    cert = load_pem_x509_certificate(cert.encode('ascii'))
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    ocsps = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
    if not ocsps:
        raise Exception(f'no ocsp server entry in AIA')
    return ocsps[0].access_location.value

def verify_certificate_chain(hostname,x509):
    context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    context.load_verify_locations(cafile = certifi.where())
    connection = OpenSSL.SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    host_ip = socket.gethostbyname(hostname)
    connection.connect((host_ip, 443))
    connection.do_handshake()
    # Get the peer certificates
    cert_chain = connection.get_peer_cert_chain()
    # Close the connection
    connection.shutdown()
    connection.close()
    try:
        store = OpenSSL.crypto.X509Store()
        store.load_locations(cafile = certifi.where())
        store.add_cert(cert_chain[-1])
        if(len(cert_chain) > 1):
            if(cert_chain[0].get_subject() != x509.get_subject()):
                try:
                    store_ctx = OpenSSL.crypto.X509StoreContext(store,cert_chain[0],cert_chain[1:-1])
                    store_ctx.verify_certificate()
                except:
                    return -1
            else:    
                store_ctx = OpenSSL.crypto.X509StoreContext(store,cert_chain[0],cert_chain[1:-1])
        else:
            return 2 #certificate chain fail
        store_ctx.verify_certificate()
        return 0 #verified
    except Exception as e:
        return 1 #not verified

def expiry_checker(certificate_info):
    expiry_date_after = certificate_info['not_after']
    expriy_date_before = certificate_info['not_before']
    current_date = datetime.utcnow()
    if current_date > expiry_date_after or current_date < expriy_date_before:
        return False
    else:
        return True

def protocol_checker(hostname, certificate_info):
    DEFAULT_TIMEOUT = 5
    results = scan_server(
        ConnectionSettings(
            host=hostname,
            timeout_in_seconds = DEFAULT_TIMEOUT
        ),
        do_enumerate_groups = False
    )
    protocols_allowed = []
    cipher_suites = []
    for i in results.protocols:
        if(results.protocols[i] != None):
            for j in results.protocols[i].cipher_suites:
                if(j in cipher_suites):
                    continue
                else:
                    cipher_suites.append(j)
            protocols_allowed.append(i)
    key_type = results.certificate_chain[0].key_type
    key_length = results.certificate_chain[0].key_length_in_bits
    certificate_info['key_type'] = key_type
    certificate_info['key_length'] = key_length
    return certificate_info, protocols_allowed, cipher_suites
def get_ocsp(hostname,cert):
    try:
        
        url = get_ocsp_server(cert)
    except:
        url = ""
    try :
##        print(ocspchecker.get_ocsp_status(hostname))
        return (ocspchecker.get_ocsp_status(hostname)[2].lstrip("OCSP Status: "),
                ocspchecker.get_ocsp_status(hostname)[1].lstrip("OCSP URL: "))
    except:
        return "Unknown",url

def get_crls(certificate_info):
    pattern = r'URI:(\S+)'
    if "crlDistributionPoints" in certificate_info:
        return re.findall(pattern, certificate_info["crlDistributionPoints"])
    else:
        return []

def is_in_crl(serial_number, crl_list):
    for crl_url in crl_list:
        resp = requests.get(crl_url)
        crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, resp.content)
        if crl.get_revoked():
            rev_serial_numbers = [rev.get_serial().decode() for rev in crl.get_revoked()]
            if serial_number in rev_serial_numbers:
                return True
    return False

def grade_certificate(certificate_info):
    score = 0

    if(not expiry_checker(certificate_info) or not certificate_info['verified'] or certificate_info["revoked"] or certificate_info["ocsp_status"] == "REVOKED"):
       score = 0
    elif("sha1" in certificate_info['signature_algorithm']):
        score = 30
    elif("md5" in certificate_info['signature_algorithm']):
        score = 20
    elif(not certificate_info['chain']):
        score = 50
    elif(certificate_info["ocsp_status"] == "UNKNOWN"):
        score = 70
    else:
        score = 100
    return score


def grade_protocols(protocols_allowed):
    protocol_list = ["SSLv3","TLS1_0","TLS1_1","TLS1_2","TLS1_3"]
    protocols_allowed_format = str(protocols_allowed).replace('[',"").replace(']',"")
    min_protocols = ""
    for i in protocol_list:
        if(str(i) in protocols_allowed_format):
            min_protocols = i
            break
    if("SSLv3" in min_protocols):
        return 20
    elif("TLS1_0" in min_protocols):
        return 60
    elif("TLS1_1" in min_protocols):
        return 80
    else:
        return 100

def grade_key_exchange(key_type, key_length):
    #https://www.researchgate.net/figure/Security-and-Key-length-Comparison-of-ECC-vs-RSA-DSA-DH_tbl2_309097688
    #RSA/DSA 2048 = 112 bits
    #EC 256 = 128 bits
    if(key_type == "RSA" or key_type== "DSA"):
        if(key_length < 1024):
            return 10
        elif(key_length < 2048):
            return 30
        elif(key_length < 3072):
            return 90
        else:
            return 100
    elif(key_type == "EC"):
        if(key_length < 160):
            return 10
        elif(key_length < 224):
            return 30
        elif(key_length < 256):
            return 90
        else:
            return 100
    else:
        #no key found
        return 0


def grade_cipher_suites(cipher_suites):
    scores = {}
    for cipher in cipher_suites:
        ciph = str(cipher).replace("CipherSuite.","")
        if(ciph in CIPHERS_RANKING):
            scores[ciph] = CIPHERS_RANKING[ciph]
        else: #it is weak
            scores[ciph] = 60
    
    return min(scores.values())



def grader(certificate_info, protocols_allowed, cipher_suites):
    certificate_grade = grade_certificate(certificate_info)
    protocols_grade = grade_protocols(protocols_allowed)
    key_exchange_grade = grade_key_exchange(certificate_info["key_type"],certificate_info["key_length"])
    cipher_suites_grade = grade_cipher_suites(cipher_suites)

    grade = ""
    if(min(certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade) == 100):
        grade = "A+"
    elif(min(certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade) >=90):
        grade = "A"
    elif(min(certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade) >=80):
        grade = "B+"
    elif(min(certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade) >=70):
        grade = "B"
    elif(min(certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade) >=60):
        grade = "C+"
    elif(min(certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade) >=50):
        grade = "C"
    elif(min(certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade) >=40):
        grade = "D+"
    elif(min(certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade) >=30):
        grade = "D"
    elif(min(certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade) >=20):
        grade = "E"
    else:
        grade = "F"

    return certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade, grade
    

def output_skeleton(certificate_info, protocols_allowed, cipher_suites, to_csv):
    certificate_grade, protocols_grade, key_exchange_grade, cipher_suites_grade, grade = grader(certificate_info,protocols_allowed,cipher_suites)
    new_data =  {'domain' : certificate_info['hostname'], 'certificate_grade' : certificate_grade , 'protocols_grade' :protocols_grade ,
                 'key_exchange_grade' : key_exchange_grade, 'cipher_suites_grade' : cipher_suites_grade, 'grade' : grade} 
    
    print(certificate_info['not_after'])
    print(certificate_info['not_before'])
    print("Server = ", certificate_info['hostname'])
    print(f"Certificate      : {certificate_grade}/100")
    print(f"Protocol Support : {protocols_grade}/100")
    print(f"Key Exchange     : {key_exchange_grade}/100")
    print(f"Cipher Strength  : {cipher_suites_grade}/100\n")

    print(f"Overall Grade    : {grade}\n")

    print("Common Name = ", certificate_info["subject"]["CN"])
    print("Subject Alternative Names = ", certificate_info["subject_alt_name"])
    print("Issuer = ", certificate_info["issuer"]["CN"])
    print("Serial Number = ", certificate_info["serial_number"])
    print("SHA256 Fingerprint = ", certificate_info['sha256_fingerprint'])
    print("Key Type = ",certificate_info['key_type'])
    print("Key Length = ",certificate_info['key_length'])
    print("Signature_algorithm = ",certificate_info["signature_algorithm"])

    print("\nSecure Negotiation:")
    print(f"OCSP Origin  :{certificate_info['ocsp_origin']}")
    print(f"OCSP Staple  :{certificate_info['ocsp_status']}")
    crl_status = "GOOD" if not certificate_info['revoked'] else "BAD"
    print(f"CRL Status   :{crl_status}")
    protocol_list = {"SSLv3" : "SSLv3","TLS1_0": "TLSv1.0","TLS1_1": "TLSv1.1","TLS1_2": "TLSv1.2","TLS1_3": "TLSv1.3"}
    
    # Format the datetime object
    formatted_date = certificate_info['not_after'].strftime("%B %d, %Y")
    current_datetime = datetime.now()
    time_difference = certificate_info['not_after'] - current_datetime
    print(f"\nThe certificate expires {formatted_date} ({time_difference.days} days from today)")
    
    print("\nProtocol Support: ",end = "")
    comma = False
    for i in protocols_allowed:
        if(not comma):
            comma = True
        else:
            print(", ",end="")
        protocol = str(i).replace("Protocol.","")
        print(protocol_list[protocol],end="")
    print("\n")

    print("\nTLS Cipher Supported By The Server:\n")
    print(str(cipher_suites).replace("[","").replace("]",""))
    
##################################
#Main

hostname = "dbs.com"

certificate_info,x509,cert = get_certificate_info(hostname)


certificate_info['hostname'] = hostname
verified  = verify_certificate_chain(hostname,x509)

certificate_info['chain'] = True
ver = True
if(verified == 0):
    #true
    ver = True
elif (verified == 1):
    ver = False
elif ( verified == 2):
    certificate_info['chain'] = False
elif (verified == -1):
    #remove test
    raise Exception("An error occurred.")
    
certificate_info['verified'] = ver
certificate_info, protocols_allowed, cipher_suites = protocol_checker(hostname,certificate_info)    
output_skeleton(certificate_info, protocols_allowed, cipher_suites, to_csv)


