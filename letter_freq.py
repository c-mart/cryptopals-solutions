import re

"""
Quick & dirty: building a Python dictionary from letter frequency table copypasted from Wikipedia.
https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
"""

text = """
a 	8.167%

b 	1.492%

c 	2.782%

d 	4.253%

e 	12.702%

f 	2.228%

g 	2.015%

h 	6.094%

i 	6.966%

j 	0.153%

k 	0.772%

l 	4.025%

m 	2.406%

n 	6.749%

o 	7.507%

p 	1.929%

q 	0.095%

r 	5.987%

s 	6.327%

t 	9.056%

u 	2.758%

v 	0.978%

w 	2.361%

x 	0.150%

y 	1.974%

z 	0.074%
"""

text_list = text.split('\n')
letter_freq_dict = dict()
for line in text_list:
    match = re.search("([a-z]).*([0-9]\.[0-9]+)%.*", line)
    if match:
        letter_freq_dict[match.group(1)] = float(match.group(2))
