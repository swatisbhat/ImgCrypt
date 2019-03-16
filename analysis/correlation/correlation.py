from PIL import Image
import numpy

img1='img1.bmp'
img1_e='e_img1.bmp'
img2='new_img1.bmp'
img2_e='e_new_img1.bmp'

im1 = numpy.array(Image.open(img1))
im1_e = numpy.array(Image.open(img1_e))

im2 = numpy.array(Image.open(img2))
im2_e = numpy.array(Image.open(img2_e))

err1 = numpy.sum((im1.astype('float')-im2.astype('float'))**2)
err1/=float(im1.shape[0]*im1.shape[1])

err1_e = numpy.sum((im1_e.astype('float')-im2_e.astype('float'))**2)
err1_e/=float(im1_e.shape[0]*im1_e.shape[1])

print "MSE for similar test images : {}\n".format(err1)
print "MSE for encrypted test images : {}\n".format(err1_e)
