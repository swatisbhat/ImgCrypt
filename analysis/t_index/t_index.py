import matplotlib.pyplot as plt
import json

tindex_for_key_1 = open('abcdefghijklmnop_tindex.txt')
tindex_1 = json.load(tindex_for_key_1)
tindex_1 = tindex_1[0:50]

x = range(0,len(tindex_1))
plt.plot(x, tindex_1)
plt.savefig('abcdefghijklmnop_tindex.png')
plt.show()

tindex_for_key_2 = open('abcdefghijklmnoq_tindex.txt')
tindex_2 = json.load(tindex_for_key_2)
tindex_2 = tindex_2[0:50]

x = range(0,len(tindex_2))
plt.plot(x, tindex_2)
plt.savefig('abcdefghijklmnoq_tindex.png')
plt.show()


