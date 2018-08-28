from mydnsresolver_dnssec import iterative_resolver
import sys
import time

if __name__ == "__main__":
    hostname = sys.argv[1]
    type = sys.argv[2]
    #print "hostname is:", hostname
    #print "type:", type

    start_time = time.time()
    iterative_resolver(hostname, type, start_time, 1)
    #print "Done."
