# CDL_Fuzzing

## pre research
before I implement the task I was should to discover how to detect fuzzing.</br>
so I created 2 vm and log on from one to the other by ssh.</br>
then I notices that every time I insert bad password I get message with const length of 104.</br>
so I decided that if I get more then 5 bad password in a row I report fuzzing.</br>
I also notices that for every normal size password the message length 200,</br>
and when I get to long password or long data the massage is bigger so 200.</br>
so I decided that if I get more then 5 massages that the password is to long I can assume that this is a garbage,</br>
and raptor it as fuzzing detected.</br>

</br>
I also run kail linux on vm and run fuzzing from it and I notices that there are to long massages that are garbage.</br>
so again when I get very big massage I understand this is garbage and after some messages like that I report.</br>
and I saw that if the load in the Raw shows  "b'Invalid SSH identification string.'" so the massage I get isn't ssh message.</br>
so when I get lot of massages like that I can assume I get fuzzing</br>
and I also check if I can read the massage and if I can I check that the same 

## how to run the program
at the begin you need to install scapy on your computer</br>
after that go to the project folder CDL_Fuzzing</br>
and run sudo python3 fuzzing.py</br>
insert the name of the network</br>

## about the project
my code is written in python</br>
at the beginning we defined the number of bad massages I get before report as report number</br>
I also defined 3 counters named num_fail_detected_by_len, num_bad_detevted_by_big_size, num_bad_detected_by_message.</br>
every one count different kind of bad massage.</br>
then we ask the user to insert the name of the network that we will lisen to</br>
</br>
the program run in loop(while 1) and every time it will.</br>
use scapy library to sniff 1 pocket in tcp and port 22(ssh pocket).</br>
after I got the packet we check the pocket length in the IP header.</br>
if the pocket length is 104 I add 1 to the  num_fail_detected_by_len counter (explain in the begging why it is bad).</br>
if the pocket length is bigger the 200 I add 1 to the  num_bad_detevted_by_big_size counter (explain in the begging why it is bad).
</br>
then I check the massage in the Raw header if the load is equal to "b'Invalid SSH identification string.'",<br>
so it is bad massage and we add one to the num_bad_detected_by_message counter(explain in the begging why it is bad).</br>
</br>
i check every time if one of the counter pass the number of bad massages that I can get in 1 minute.</br>
and if I do I write fuzzing and go out.</br>
if I don't detected fuzzing so I run again into the loop.</br>
</br>
and I also set timer that every some time the we defined in the beginning I set all the counter to 0.</br>
because I want that all the bad massages will be in the same time.</br>
