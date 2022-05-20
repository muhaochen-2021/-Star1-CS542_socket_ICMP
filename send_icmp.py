import os
import socket
import struct
import sys
import threading # because the sending and receiving are simultaneous
import time

# define the parameters
# 1. the bit length of payload data
payload_data_bit_length = 256 
# 2. define the type of message
message_type = "ICMP"
# 3. reveiver ip address
rec_ip_address = "192.168.50.202"
# 4. how many times you wanna to send, sum_times = icmp_nums*2, because two icmp one time
icmp_nums = 1
# 5. sending number
sending_num = 0
# 6. reveving number
receving_num = 0
# 7. time_list
time_list = []

# generate the data through func, based on bit length required, such as 256.
def generate_payload_data(bit_length):
    payload_data = 1
    while(True):
        if payload_data.bit_length() == 256:
            break
        payload_data = payload_data * 2
    # change the int to bytes
    payload_data = b'%d'%(payload_data)
    return payload_data

# define and create the socket
def create_socket(message_type):
    obj_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname(message_type))
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

def send_icmp(obj_socket, rec_ip_address, identify_num, payload_data):
    # set sequence number
    sequence_number = 1
    icmp_nums_sum = icmp_nums * 2
    while sequence_number < icmp_nums_sum+1:
        print("======================================sending=============================================")
        print("start sending icmp,round: ",str(sequence_number//2+1))
        print("==========================================================================================")
        for i in range(2):
            print("start sending, sequence number: ",sequence_number)
            # record the current time
            time_start = time.time()
            # add the time to the payload
            payload_add_time = struct.pack('!d', time_start) + payload_data
            # pack icmp using struct, 8 is request, code is 0
            type_request = 8
            type_code = 0
            # pack icmp using struct
            icmp_before_checksum = struct.pack('!BBHHH',type_request,type_code,0,identify_num,sequence_number,)+payload_add_time
            # compute checksum based on raw icmp
            checksum = get_checksum(icmp_before_checksum)
            # add checksum to the final sending icmp
            icmp = icmp_before_checksum[:2] + checksum + icmp_before_checksum[4:]
            # send the icmp to the deitination
            obj_socket.sendto(icmp, 0, (rec_ip_address, 0))
            print("finish sending, sequence number: ",sequence_number)
            # sequence ++
            sequence_number = sequence_number + 1
            # send num plus 1
            global sending_num
            sending_num = sending_num + 1
        print("==========================================================================================")
        time.sleep(3)
    return None

def receive_icmp(obj_socket, identify_num):
    while True:
        try:
            # listen the port, wait the reply icmp
            icmp_reply, reply_address_tuple = obj_socket.recvfrom(1000)
            print(" ")
            print("*******************************************receive reply***********************************************")
            reply_address = reply_address_tuple[0]
            # unpack the struct to get the data
            icmp_reply_process = icmp_reply[20:]
            reply_type, reply_code, v1, current_ident, sequence_number, = struct.unpack('!BBHHH',icmp_reply_process[:8])
            # judge reply type is 0, whether code is 0
            if (reply_type != 0) or (reply_code != 0): 
                pass
            payload = icmp_reply_process[8:]
            #judge whether there are any return , judge whether there are the same identify number, true rply, not other icmp
            if (current_ident != identify_num) and current_ident: 
                pass
            # get the sending time from the reply, compute the time period
            sending_time, = struct.unpack('!d', payload[:8])
            period_time = (time.time()-sending_time) * 1000
            period_time = round(period_time,4)
            print("sequence_number: ",sequence_number)
            print("id_address_reveiver: ",reply_address)
            print("time_period: ",period_time," ms")
            # get the content
            print("content/payload: ")
            print_payload = str(payload[8:])[2:-1]
            print(print_payload)
            print("*******************************************************************************************************")
            print(" ")
            # write into the txt
            with open('sender_receve_replies_data_icmp'+str(sequence_number)+'.txt','w') as f:   
                f.write(print_payload)                 
            # rece num plus 1
            global receving_num
            receving_num = receving_num + 1
            time_list.append(period_time)
            if sequence_number == 2:
                # show the statistics
                gene_stats()
                break
        except:
            continue

# generate statistics
def gene_stats():
    print("++++++++++++++++++++++++++++++++++++statistics++++++++++++++++++++++++++++++++++++")
    print("total sending number: ",sending_num)
    print("total reply number: ",receving_num)
    print("loss rate: ",round((sending_num-receving_num)/receving_num,2))
    print("max pass time: ",max(time_list))
    print("min pass time: ",min(time_list))
    print("average pass time: ",round(sum(time_list)/len(time_list),3))
    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

# create socket
obj_socket = create_socket(message_type)
# identify number 
identify_num = 3400
# generate the data on payload
payload_data = generate_payload_data(payload_data_bit_length)
# two threads, including sending messages and receiving replies
# thread one, put parameters into the args
args = (obj_socket, rec_ip_address, identify_num, payload_data)
# put the func to the thread
thread1_sender = threading.Thread(target=send_icmp, args=args)
# start sending
thread1_sender.start()
# keep listenting to wait for the reply
receive_icmp(obj_socket, identify_num)
# clean sender thread
thread1_sender.join()