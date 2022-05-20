import os
import socket
import struct
import sys
import time

# 1. define the type of message
message_type = "ICMP"
# 2. how many times you wanna to send, sum_times = icmp_nums*2, because two icmp one time
icmp_nums = 1

# define and create the socket
def create_socket(message_type):
    obj_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname(message_type))
    if sys.platform == 'win32':
        # windows require the binding, i do not know why
        # https://docs.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2
        obj_socket.bind(("192.168.50.202", 0))
        obj_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return obj_socket

def get_checksum(icmp_before_checksum):
    # set checksum value
    checksum = 0
    # get the legth of icmp before checksum
    icmp_before_checksum_length = len(icmp_before_checksum)
    # if check sum could not be divided by 2, add \00
    if (icmp_before_checksum_length % 2):
        icmp_before_checksum = icmp_before_checksum + b'\00'
    # compute how many two btyes word
    len_two_B_icmp = len(icmp_before_checksum)//2
    # get every two bytes word 
    for i in range(len_two_B_icmp):
        byte_content = struct.unpack('!H', icmp_before_checksum[2*i:2*i+2])[0]
        checksum += byte_content
    # transfer into checksum
    more_than_16bit = checksum >> 16
    while more_than_16bit:
        more_than_16bit = checksum >> 16
        checksum = (checksum & 0xffff) + more_than_16bit
    # reverse the code
    checksum = ~checksum & 0xffff
    checksum = struct.pack('!H', checksum)
    return checksum

def receive_icmp(obj_socket, identify_num):
    while True:
        try:
            # listen the port, wait the reply icmp
            icmp_reply, reply_address_tuple = obj_socket.recvfrom(1000)
            print(" ")
            print("*******************************************receive icmp************************************************")
            reply_address = reply_address_tuple[0]
            reply_address = "192.168.50.133"
            # unpack the struct to get the data
            icmp_reply_process = icmp_reply[20:]
            reply_type, reply_code, v1, current_ident, sequence_number, = struct.unpack('!BBHHH',icmp_reply_process[:8])
            payload = icmp_reply_process[8:]
            #judge whether there are any return , judge whether there are the same identify number, true rply, not other icmp
            if (current_ident != identify_num) and current_ident: 
                pass
            # get the sending time from the reply, compute the time period
            sending_time, = struct.unpack('!d', payload[:8])
            print("sequence_number: ",sequence_number)
            print("id_address_reveiver: ",reply_address)
            # get the content
            print("content/payload: ")
            print_payload = str(payload[8:])[2:-1]
            print(print_payload)
            print("*******************************************************************************************************")
            print(" ")
            # write into the txt
            with open('reveiver_receive_data_icmp'+str(sequence_number)+'.txt','w') as f:   
                f.write(print_payload)                 
            if sequence_number == 2:
                return reply_address,print_payload,sending_time
        except:
            continue

def send_icmp(obj_socket, rec_ip_address, identify_num, payload_data,sending_time):
    # set sequence number
    sequence_number = 1
    icmp_nums_sum = icmp_nums * 2
    while sequence_number < icmp_nums_sum+1:
        print("======================================sending=============================================")
        print("start sending icmp,round: ",str(sequence_number//2+1))
        print("==========================================================================================")
        for i in range(2):
            print("start sending, sequence number: ",sequence_number)
            # add the time to the payload
            payload_add_time = struct.pack('!d', sending_time) + payload_data
            # pack icmp using struct, 8 is request, code is 0
            type_request = 0
            type_code = 0
            # pack icmp using struct
            icmp_before_checksum = struct.pack('!BBHHH',8,type_code,0,identify_num,sequence_number,)+payload_add_time
            # compute checksum based on raw icmp
            checksum = get_checksum(icmp_before_checksum)
            # add checksum to the final sending icmp
            icmp = icmp_before_checksum[:2] + checksum + icmp_before_checksum[4:]
            # send the icmp to the deitination
            obj_socket.sendto(icmp, 0, (rec_ip_address, 0))
            print("finish sending, sequence number: ",sequence_number)
            # sequence ++
            sequence_number = sequence_number + 1
        print("==========================================================================================")
        time.sleep(3)
    return None

# create socket
obj_socket = create_socket(message_type)
# identify number 
identify_num = 3400
# keep listenting to wait for the reply
print("start to keep listening: ")
rec_ip_address,payload_data,sending_time = receive_icmp(obj_socket, identify_num)
# turn payload data to 2 bits
payload_data = b'%d'%(int(payload_data))
# start to reply
print("start to reply: ")
send_icmp(obj_socket, rec_ip_address, identify_num, payload_data,sending_time)