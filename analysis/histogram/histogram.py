import cv2
import numpy as np
from matplotlib import pyplot as plt

file0 = 'encrypted_dog'
file1 = file0+'.bmp'
img = cv2.imread(file1)
color = ('b','g','r')
plt.figure()
for i,col in enumerate(color):
    histr = cv2.calcHist([img],[i],None,[256],[0,256])
    plt.plot(histr,color = col)
    plt.xlim([0,256])
    plt.ylim([0,300])
    plt.savefig('histogram_'+col+'_'+file0+'.png')

