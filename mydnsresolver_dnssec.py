import dns
import dns.name
import dns.message
import dns.query
import dns.flags
import time
import datetime
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3

root_server_list = ['192.5.5.241', '192.203.230.10', '192.112.36.4', '198.97.190.53', '192.58.128.30', '199.9.14.201', '199.7.91.13', '192.33.4.12', '192.36.148.17', '193.0.14.129', '202.12.27.33', '199.7.83.42', '198.41.0.4']

Prev_DS_Key = None

def validate(name, ns):

    #print "in validation"
    global Prev_DS_Key
    #print "Before Prev_DS_Key:", Prev_DS_Key
    #print name
    s = "."
    if (name.find('.')!=-1):
        parent = name[name.index(s) + len(s):]
    else:
        parent = "."
    #print parent
    #print ns

    request = dns.message.make_query(parent, dns.rdatatype.DNSKEY, want_dnssec=True)
    try:
        response1 = dns.query.tcp(request, ns, timeout = 1)
        #print "response1:", response1
    except dns.exception.Timeout:
        print "timeout"

    request = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True)
    try:
        response2 = dns.query.tcp(request, ns, timeout = 1)
        #print "response2:", response2
    except dns.exception.Timeout:
        print "timeout"

    parent_t = dns.name.from_text(parent)

    DNSkey = response1.answer[0]
    try:
        dns.dnssec.validate(response1.answer[0], response1.answer[1], {parent_t:response1.answer[0]})
        print "DNSSEC validation pass 1 done"
    except dns.dnssec.ValidationFailure:
        print "DNSSEC validation failed"
        exit()

    if(len(response2.answer) > 0):
        DS = response2.answer[0]
        rrsig_DS = response2.answer[1]
    else:
        DS = response2.authority[1]
        rrsig_DS = response2.authority[2]

    if (isinstance(DS[0], dns.rdtypes.ANY.NSEC.NSEC) or isinstance(DS[0], dns.rdtypes.ANY.NSEC3.NSEC3)):
        print "DNSSEC not supported"
        exit()

    else:
        try:
            dns.dnssec.validate(DS, rrsig_DS, {parent_t:response1.answer[0]})
            print "DNSSEC validation pass 2 done"
        except dns.dnssec.ValidationFailure:
            print "DNSSEC validation failed"
            exit()

        for entry in DNSkey:
            str_tokens = str(entry).split(" ")
            if(str_tokens[0] == '257'):
                new_DS = dns.dnssec.make_ds(parent_t, entry, 'SHA256')
                #print "new_DS", new_DS
                if Prev_DS_Key != None:
                    if Prev_DS_Key[0] == new_DS:
                        print "DNSSEC validation pass 3 done"
                        Prev_DS_Key = DS
                        break
                    else:
                        print "DNSSEC validation failed"
                        exit()
                else:
                    print "DNSSEC validation pass 3 skipped at root"
                    Prev_DS_Key = DS
                    #print "Prev_DS", Prev_DS_Key
                    break

    #print "After Prev_DS_Key:", Prev_DS_Key

def print_result(response, start_time):
    msg_size = 0
    print "\nQUESTION SECTION:"
    for rrset in response.question:
        print rrset
        msg_size += len(str(rrset))
    if(len(response.answer) > 0):
        print "\nANSWER SECTION:"
        for rrset in response.answer:
            print rrset
            msg_size += len(str(rrset))
    if(len(response.authority) > 0):
        print "\nAUTHORITY SECTION:"
        for rrset in response.authority:
            print rrset
            msg_size += len(str(rrset))

    print "\nQuery time:", int(round((time.time() - start_time)*1000)), "msec"

    now = datetime.datetime.now()
    print "\nWHEN:", str(now)

    print "MSG SIZE  rcvd:", msg_size
    print "\n"


def single_query_resolver(name, dns_server, type, validation):
    #print "in single_query_resolver.."
    if (type == 'A'):
        request = dns.message.make_query(name, dns.rdatatype.A)
    elif (type == 'NS'):
        request = dns.message.make_query(name, dns.rdatatype.NS)
    elif (type == 'MX'):
        request = dns.message.make_query(name, dns.rdatatype.MX)
    else:
        print "Unsupported Type, this program supports only A, NS or MX"
        exit()

    try:
        response = dns.query.udp(request, dns_server, timeout = 1)
        #validation
        if(validation == 1):
            validate(name, dns_server)
    except dns.exception.Timeout:
        #print "dns udp query timeout"
        return None
    return response

def iterative_resolver(name, type, start_time, print_res):
    #print "\n iterative function started for:"
    #print name
    if name.endswith('.'):
        name = name[:-1]
    mytokens = name.split(".")
    mytokens.reverse()
    query_input = mytokens[0]
    i = 1
    #Prev_DS_Key.append(0)

    for rootns in root_server_list:
        while(i < len(mytokens)+1):
            #print "i:", i
            #print "while in:", query_input
            #print "while ns:", rootns
            query_response = single_query_resolver(query_input, rootns, type, 1)
            #print "res:", query_response
            if (query_response != None):
                if(query_response.rcode() == dns.rcode.NOERROR):
                    if(len(query_response.answer) > 0):
                        #print "We have resolved the IP and it is present in Answer section
                        if(query_response.flags & dns.flags.AA ==  dns.flags.AA):
                            for rdata in query_response.answer:
                                if(rdata.rdtype == 1 or rdata.rdtype == 2 or rdata.rdtype == 15):
                                    if(print_res == 1):
                                        print_result(query_response, start_time)
                                    return query_response
                                if(rdata.rdtype == 5): #CNAME
                                    #print "CNAME case.."
                                    if(type == 'NS' or type == 'MX'):
                                        if(print_res == 1):
                                            print_result(query_response, start_time)
                                        return query_response
                                    #print (rdata[0].target)
                                    iterative_resolver(str(rdata[0].target), type, start_time, 1)
                                    return query_response

                    else:
                        #We did not get answer so checking additional servers
                        #print "Checking additional servers list"
                        if(len(query_response.additional) > 0):
                            for rdata in query_response.additional:
                                if(rdata.rdtype == 1):
                                    rootns = rdata[0].address
                                    if(i < len(mytokens)):
                                        #print "append 1"
                                        query_input = mytokens[i] + "." + query_input
                                        i += 1
                                        check_response = single_query_resolver(query_input, rootns, type, 0)
                                        if(check_response != None):
                                            break
                                        else:
                                            #print "trying next additional server"
                                            continue
                                    #new trial
                                    else:
                                        #print "not a complete name case"
                                        query_response = single_query_resolver(query_input, rootns, type, 0)
                                        if(query_response != None):
                                            if(len(query_response.answer) > 0 and (type == 'NS' or type == 'MX')):
                                                if(print_res == 1):
                                                    print_result(query_response, start_time)
                                                return query_response

                                            if(len(query_response.answer) > 0):
                                                if(query_response.flags & dns.flags.AA ==  dns.flags.AA):
                                                    for rdata in query_response.answer:
                                                        if(rdata.rdtype == 5): #CNAME
                                                            if(type == 'NS' or type == 'MX'):
                                                                if(print_res == 1):
                                                                    print_result(query_response, start_time)
                                                                return query_response
                                                            query_response = iterative_resolver(str(rdata[0].target), type, start_time, 1)
                                                            #if(print_res == 1):
                                                            #    print_result(query_response, start_time)
                                                            #return query_response
                                                        if(rdata.rdtype == 1):
                                                            if(print_res == 1):
                                                                print_result(query_response, start_time)
                                                            return query_response
                                            if(len(query_response.authority) > 0):
                                                for rdata in query_response.authority:
                                                    if(rdata.rdtype == 6):
                                                        if(print_res == 1):
                                                            print_result(query_response, start_time)
                                                        return query_response
                                        else:
                                            #print "trying next additional server"
                                            continue
                        else:
                            #new trial2
                            if(len(query_response.authority) > 0 and (type == 'NS' or type == 'MX')):
                                if(print_res == 1):
                                    print_result(query_response, start_time)
                                return query_response
                            #new trial2

                            #print "Special case handling"

                            #print query_input
                            if(len(query_response.authority) > 0):
                                for rdata in query_response.authority:
                                    if(rdata.rdtype == 6 or rdata.rdtype == 2):
                                        if(i < len(mytokens)):
                                            #print "append 2"
                                            query_input = mytokens[i] + "." + query_input
                                            i += 1
                                        #print query_input
                                        #print rootns
                                        query_response = single_query_resolver(query_input, rootns, type, 0)
                                        if(query_response != None):
                                            #print "response:", query_response
                                            for rdata1 in query_response.authority:
                                                if(rdata1.rdtype == 2):
                                                    #resolving NS server from the authority section
                                                    t_response = iterative_resolver(str(rdata1[0].target), type, start_time, 0)
                                                    if(t_response != None):
                                                        if(len(t_response.answer) > 0):
                                                            for rdata2 in t_response.answer:
                                                                if(rdata2.rdtype == 1):
                                                                    rootns = rdata2[0].address
                                                                    check_response = single_query_resolver(query_input, rootns, type, 0)
                                                                    if(check_response != None):
                                                                        break
                                                                    else:
                                                                        continue
                                                            query_response = single_query_resolver(query_input, rootns, type, 0)
                                                            if(print_res == 1):
                                                                print_result(query_response, start_time)
                                                            return
                                                        else:
                                                            continue
                                                    else:
                                                        continue
                                        else:
                                            continue
            else:
                break
            #i += 1

        #print "trying next root server.."

    print "Error: Given hostname could not be resolved.."
