# traceroute
An implementation of ping() and traceroute(), mirroring the CLI commands of the same name.

An implementation of ping() and traceroute(), mirroring the CLI commands of the same name. Ping sends echo requests to the target, displaying the
results, and Traceroute sends echo requests in increasing increments until the target is reached, displaying the results to map the pathway through the internet to the host.

Within IcmpHelperLibrary.py, at the bottom of the file, there is a method “main()”. Within this method, there are several lines of commented out commands. These consist of function calls of either “Ping()”, or “Traceroute()”, with an argument of a web address or an IPv4 address. To run the program, uncomment one of the lines and type “python IcmpHelperLibrary.py” from within the project directory (the implementation is in Python). If the current call within main() is a ping() call, the program will send 4 (this can be changed within the code) echo requests to the host. The program will display the results of each request, including the TTL, RTT, Type, Code, Code Description, and IP address. The program will also display the number of packets lost, the minimum RTT, the maximum RTT, and the average RTT. If the call is to traceroute(), the program will send echo requests with increasing TTLs, starting at 1. For each request, the results are displayed, including the TTL, RTT, Type, Code, Explanation, IP address, and if applicable, the name of the host where the TTL expired. By incrementing TTL each echo request, the program is able to ‘map’ a route to the destination address. For the clearest results, only run one ping or traceroute command at a time.


Citation: Code for this program is based on the description of ping() and traceroute() from 'Computer
Networking: A Top Down Approach, by Kurose and Ross', and built on starter code provided by the course
