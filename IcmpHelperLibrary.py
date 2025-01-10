""""    Mark Roetcisoender
        roetcism@oregonstate.edu
        CS372
        Assignment 3 TraceRoute
        An implementation of ping() and traceroute(), mirroring the CLI commands of the same name. To run, 
        call either ping() or traceroute() in main() with a website or echo request as the parameter, and call
        'python IcmpHelperLibrary()' in the command line. Ping sends echo requests to the target, displaying the
        results, and Traceroute sends echo requests in increasing increments until the target is reached,
        displaying the results to map the pathway through the internet to the host. 
        
        Citation: Code for this program is based on the description of ping() and traceroute() from 'Computer
        Networking: A Top Down Approach, by Kurose and Ross', and built on starter code provided by the course
        """


# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select
from socket import gethostbyname, gethostbyaddr


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #                                                                                                        #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30                # default of 30
        __ttl = 255                     # Time to live/default 255
        __cumulative_time = 0           # used to pass RTT 'up the chain'
        __good_pkts = 0                 # used to track the number of valid packet responses
        __return_addr = ""              # used to track address where icmp response originated



        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl
        
        def getReturnAddr(self):
            return self.__return_addr

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setReturnAddr(self, addr):
            self.__return_addr = addr

        def updateTotalRTT(self, rtt):
            self.__cumulative_time += rtt

        def getTotalRTT(self):
            return self.__cumulative_time
        
        def incrementValidPackets(self):
            self.__good_pkts += 1

        def getValidPackets(self):
            return self.__good_pkts
        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            icmpReplyPacket.setIsValidResponse(False)

            # compare sequence number and update boolean if match. Print debug message
            if self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber():
                icmpReplyPacket.setIcmpSeqNum_isValid(True)
            print(f'Expected Sequence Num: {self.getPacketSequenceNumber()} Received Sequence Num: {icmpReplyPacket.getIcmpSequenceNumber()}') if self.__DEBUG_IcmpPacket else 0
            
            # compare packet number and update boolean if match. Print debug message
            if self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier():
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
            print(f'Expected Packet Num: {self.getPacketIdentifier()} Received Packet Num: {icmpReplyPacket.getIcmpIdentifier()}') if self.__DEBUG_IcmpPacket else 0


            # compare data and update boolean if match. Print debug message
            if self.getDataRaw() == icmpReplyPacket.getIcmpData():
                icmpReplyPacket.setIcmpData_isValid(True)
            print(f'Expected Data: {self.getDataRaw()} Received Data: {icmpReplyPacket.getIcmpData()}') if self.__DEBUG_IcmpPacket else 0

            # if all validity checks pass, update valid response
            if icmpReplyPacket.getIcmpData_isValid() is True and icmpReplyPacket.getIcmpSeqNum_isValid() is True and icmpReplyPacket.getIcmpIdentifier_isValid() is True:
                icmpReplyPacket.setIsValidResponse(True)
                return
 
        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            """Send echo request, check reply, and build echo reply packet. Sends the echo request
            packet and processes the response (or timeout)"""

            error_codes3 = {0: "destination network unreachable",
                            1: "destination host unreachable",
                            2: "destination protocol unreachable",
                            3: "destination port unreachable",
                            4: 'fragmentation needed',
                            5: "source route failed",
                            6: "destination network unreachable",
                            7: "destination host unknown",
                            8: "source host isolated",
                            9: "communication with dest network prohibited",
                            10: "communication with dest host prohibited",
                            11: "dest network unreachable for type of service",
                            12: "host network unreachable for type of service",
                            13: "Communication prohibited"}
            error_codes11 = {0: "TTL expired",
                            1: "Fragment Reassembly Time Exceeded"}
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            # create socket and try to send the echo request packet
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )
                        # print Type 11 codes
                        if icmpCode in error_codes11:
                            print(f"Error! Code: {icmpCode} Message: {error_codes11[icmpCode]}")

                    elif icmpType == 3:                         # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )
                        # print Type 3 codes
                        if icmpCode in error_codes3:
                            print(f"Error! Code: {icmpCode} Message: {error_codes3[icmpCode]}")
                        # print("Destination Unreachable!")

                    # if Echo Reply, validate data & print results if valid
                    elif icmpType == 0:
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        packet = self
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, packet)
                        rtt = icmpReplyPacket.getRTT()
                        # if packet is good, update RTT & valide packet to pass up
                        if icmpReplyPacket.getIsValidResponse() is True:
                            self.updateTotalRTT(rtt)
                            self.incrementValidPackets()
                        return      # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def sendEchoRequestTR(self):
            """For traceroute function, slightly modified version of sendEchoRequest. Sends the echo request
            packet and processes the response (or timeout)"""

            error_codes3 = {0: "destination network unreachable",
                            1: "destination host unreachable",
                            2: "destination protocol unreachable",
                            3: "destination port unreachable",
                            4: 'fragmentation needed',
                            5: "source route failed",
                            6: "destination network unreachable",
                            7: "destination host unknown",
                            8: "source host isolated",
                            9: "communication with dest network prohibited",
                            10: "communication with dest host prohibited",
                            11: "dest network unreachable for type of service",
                            12: "host network unreachable for type of service",
                            13: "Communication prohibited"}
            error_codes11 = {0: "TTL expired",
                            1: "Fragment Reassembly Time Exceeded"}
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            # create socket and try to send the echo request packet
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]
                    self.setReturnAddr(addr[0])

                    # Type 11 response (Time exceeded)
                    if icmpType == 11:
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d  (%s)  %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    error_codes11[icmpCode],
                                    addr[0]
                                )
                              )
                    # Type 3 response (Destination Unreachable)
                    elif icmpType == 3:
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d  (%s)  %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      error_codes3[icmpCode],
                                      addr[0]
                                  )
                              )
                    # Type 0 (Echo Reply). Validate data and print information
                    elif icmpType == 0:
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        packet = self
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, packet)
                        return      # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        # variables to track whether response data is valid
        __isValidResponse = False
        __IcmpIdentifier_isValid = False
        __IcmpSeqNum_isValid = False
        __IcmpData_isValid = False
        _rtt = 0                    # RTT to pass up


        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def getIcmpIdentifier_isValid(self):
            """Get method for IcmpIdentifier_isValid"""
            return self.__IcmpIdentifier_isValid

        def getIcmpSeqNum_isValid(self):
            """Get method for IcmpSeqNum_isValid"""
            return self.__IcmpSeqNum_isValid

        def getIcmpData_isValid(self):
            """Get method for IcmpData_isValid"""
            return self.__IcmpData_isValid

        def getRTT(self):
            """Get method for a packet's RTT"""
            return self._rtt

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def getIsValidResponse(self):
            return self.__isValidResponse
        
        def setIcmpIdentifier_isValid(self, value):
            """Setter method for IcmpIdentifier_isValid"""
            self.__IcmpIdentifier_isValid = value

        def setRTT(self, value):
            """Set method for a packet's RTT"""
            self._rtt = value

        def setIcmpData_isValid(self, value):
            """Setter method for IcmpData_isValid"""
            self.__IcmpData_isValid = value

        def setIcmpSeqNum_isValid(self, value):
            """Setter method for IcmpSeqNum_isValid"""
            self.__IcmpSeqNum_isValid = value

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr, packet):
            """Print resulting information from an icmp rely packet"""
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    (Success!)    Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )
            self.setRTT((timeReceived - timeSent) * 1000)
            # print comparision data if the packet is bad
            if self.isValidResponse is False:
                print(f'Expected Sequence Num: {packet.getPacketSequenceNumber()} Received Sequence Num: {self.getIcmpSequenceNumber()}') if not self.__IcmpSeqNum_isValid else 0
                # if not self.getIcmpData_isValid
                print(f'Expected Packet Num: {packet.getPacketIdentifier()} Received Packet Num: {self.getIcmpIdentifier()}') if not self.__IcmpIdentifier_isValid else 0
                print(f'Expected Data: {packet.getDataRaw()} Received Data: {self.getIcmpData()}') if not self.__IcmpData_isValid else 0

            return

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    def __sendIcmpEchoRequest(self, host):
        """Function mirroring ping(). The function sends (packet sent) echo requests. The request
        responses are recorded printed, and if Type 0 Code 0 (Destination Reached), validated. The
        function calculates RTT stats and displays it, along with the number of dropped packets"""
        
        
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # variables to track the RTT data and number of good packets
        cumulative_time = 0
        min_time = -1
        max_time = 0
        num_good_pckts = 0
        packets_sent = 4

        for i in range(packets_sent):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()                                       # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0

            # calculate RTT and valid packet data 
            cumulative_time += icmpPacket.getTotalRTT()
            if min_time == -1 and icmpPacket.getTotalRTT() > 0:
                min_time = icmpPacket.getTotalRTT()
            if icmpPacket.getTotalRTT() > 0 and icmpPacket.getTotalRTT() < min_time:
                min_time = icmpPacket.getTotalRTT()
            if icmpPacket.getTotalRTT() > max_time:
                max_time = icmpPacket.getTotalRTT()
            num_good_pckts += icmpPacket.getValidPackets()
        
        # print stats
        print(f"Ping statistics for {host}")
        print(f"Packets: Sent = {packets_sent}, Recieved = {num_good_pckts}, Lost = {packets_sent - num_good_pckts} "
              "(" + str(round(((packets_sent - num_good_pckts)/packets_sent)* 100)) +"%)")
        print("Approximate round trip times in milli-seconds:")
        if num_good_pckts == 0:
            print("Minimum = 0 ms, Maximum = 0 ms, Average = 0 ms\n All Packets Lost")
        else:
            print(f"Minimum = {round(min_time)}ms, Maximum = {round(max_time)}ms, Average = {round(cumulative_time/num_good_pckts)}ms")

    def __sendIcmpTraceRoute(self, host):
        """Function mirroring a traceroute command. The function sends echo requests, with increasing TTLs. The request
        responses are recorded and printing, mapping the route the packet takes through the internet. The
        function terminates when max_hops are reached, or the request reaches the destination host."""

        max_hops = 50
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here
        print(f"\nTracing route to {host} ({gethostbyname(host)}) over a maximum of {max_hops} hops.")

        # Send a echo request, with TLL increasing from 1 to max_hops. Create packet, send it, wait for
        # response, and print response info.
        iteration = 1
        while iteration <= max_hops:
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            icmpPacket.setTtl(iteration)

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = iteration

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequestTR()                                                # Build IP

            # if we've reached the destination, break
            if icmpPacket.getReturnAddr() == gethostbyname(icmpPacket.getIcmpTarget()):
                print(f"Trace to {host} complete\n")
                return
            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            iteration += 1
            # try to print readable address from IP if possible
            try:
                print("Address: ", gethostbyaddr(icmpPacket.getReturnAddr())[0])
            except IOError:
                continue


    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        """Initializer for ping()"""
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        """Initializer for traceroute()"""
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("200.10.227.250") # should give some type 3's
    # icmpHelperPing.sendPing("122.56.99.243")
    # icmpHelperPing.sendPing("128.119.245.12")
    # icmpHelperPing.sendPing("201.16.253.177")
    # icmpHelperPing.sendPing("www.proton.ch")
    # icmpHelperPing.sendPing("www.espn.com")
    # icmpHelperPing.sendPing("10.255.255.255") # time out
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.sendPing("www.eldinamo.cl") # Chile
    # icmpHelperPing.sendPing("www.universite-lyon.fr") # France
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")
    # icmpHelperPing.traceRoute("google.com")
    # icmpHelperPing.traceRoute("espn.com")
    # icmpHelperPing.traceRoute("greenvilleonline.com")
    # icmpHelperPing.traceRoute("200.10.227.250")
    # icmpHelperPing.traceRoute("122.56.99.243")
    # icmpHelperPing.traceRoute("baidu.com")
    # icmpHelperPing.traceRoute("200.10.227.250") # should give some type 3's
    # icmpHelperPing.traceRoute("www.cnnbrasil.com.br")
    # icmpHelperPing.traceRoute("www.eldinamo.cl")    # Chile
    # icmpHelperPing.traceRoute("www.universite-lyon.fr")
    # icmpHelperPing.traceRoute("www.nytimes.com")    # San Francisco


if __name__ == "__main__":
    main()
