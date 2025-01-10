# traceroute
An implementation of ping() and traceroute(), mirroring the CLI commands of the same name.

An implementation of ping() and traceroute(), mirroring the CLI commands of the same name. To run, 
call either ping() or traceroute() in main() with a website or echo request as the parameter, and call
'python IcmpHelperLibrary()' in the command line. Ping sends echo requests to the target, displaying the
results, and Traceroute sends echo requests in increasing increments until the target is reached,
displaying the results to map the pathway through the internet to the host.

Example targets are commented out in the 'main' section of the file.

Citation: Code for this program is based on the description of ping() and traceroute() from 'Computer
Networking: A Top Down Approach, by Kurose and Ross', and built on starter code provided by the course
