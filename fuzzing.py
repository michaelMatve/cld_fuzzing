from ast import Try
from typing import Counter
from scapy.all import *
import time
#timout time

time_stop = 1
#this is the number of bad messages i get before i report
report_number = 5

#count the number of times got pocket len 104  becouse
#I creat a ssh conction after checking the packets I notis that every time I put wrong password,
# 104 len packet is sended so if i see more then 5 wrong password i report it
num_fail_detected_by_len = 0
# I also see that if the massage is to big(len bigger from 200) this should be checked
# becouse i noties that for every password I insert the length was 200 and when I put very long like to long massage
# I get more then 200 and whis should not happand. 
# so if I get more then 5 messages with bigger size of 200 before someone logs in I report it
num_bad_detevted_by_big_size =0
# when I run auto attack from the kali computer I also noties that
# when I get bad format message we get 'Invalid SSH identification string.'  this message in the Raw
# level so I anderstand that this massages are bad and after getinng 5 messages like that i repport it
num_bad_detected_by_message = 0

#i also check that every message end in \r\n like need in ssh sintaks
num_bad_detected_by_r_n = 0

#when i see message with hax bad contact like the same char in row
num_bad_detected_by_same_char = 0

time_start = time.time()

net_name = input("insert the network name: ")

while 1:

    #we sniff one pocket from the conputer network in ptcp and port 22 
    #becouse this is ssh port and it work other tcp
    #and every time we get one and check it
    sniffed_pocket = sniff(iface=net_name,filter="tcp and port 22", count=1)[0]

    if time.time()-time_start > time_stop*60:
        num_bad_detevted_by_big_size = 0
        num_fail_detected_by_len = 0
        num_bad_detected_by_message =0
        num_bad_detected_by_r_n = 0
        num_bad_detected_by_same_char = 0
        time_start=time.time()

    # check if the packet got ip header
    if IP in sniffed_pocket:

        # check the length if is equal to 680 
        # after checking the packet we notise 680 is the size of good connction 
        # so we set all the bad counters to 0

        #add to the bad big packet counter
        if sniffed_pocket[IP].len == 104:
            num_fail_detected_by_len+=1
            # print(sniffed_pocket[IP].len)

        #add to the bad big packet counter
        if sniffed_pocket[IP].len > 200:
            num_bad_detevted_by_big_size+=1
            # print(sniffed_pocket[IP].len)

    if Raw in sniffed_pocket:
        try:
            # try to translate the data
            data_string = sniffed_pocket[Raw].load.decode()
            # check if the packet isnt good ssh packet
            if data_string == 'Invalid SSH identification string.':
                num_bad_detected_by_message+=1
            #check end with \r\n
            if data_string[len(data_string)-1] != '\n' or data_string[len(data_string)-2] != '\r':
                print(data_string)
                num_bad_detected_by_r_n+=1

            #check for same char in arow more then 15 times
            counter_char = 0
            for i in range (0,len(data_string)-1):
                if data_string[i] == data_string[i+1]:
                    counter_char +=1
                    if counter_char > 15:
                        num_bad_detected_by_same_char+=1
                        break
                else:
                    counter_char = 0
        except:
            pass       

    #if one of the counter is more then the report_number we report it
    if num_bad_detected_by_message>= report_number:
        print("fuzzing detedted")
        break
    if num_bad_detevted_by_big_size >= report_number:
        print("fuzzing detedted")
        break
    if num_fail_detected_by_len >= report_number:
        print("fuzzing detedted")
        break
    if num_bad_detected_by_same_char >= report_number:
        print("fuzzing detedted")
        break
    if num_bad_detected_by_r_n >= report_number:
        print("fuzzing detedted")
        break
   

