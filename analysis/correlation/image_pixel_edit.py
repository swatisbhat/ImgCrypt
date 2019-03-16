from PIL import Image

img=Image.open('img1.bmp')
pixels=list(img.getdata())
print pixels[0]
new_pixels=[]
count=0
new_data=(100)
new_pixels.append(new_data)
# change vaue of first pixel
pixels[0]=100
#changes just 1st pixel
for r in pixels:
    if count!=0:
        new_data=(r)
        new_pixels.append(new_data)
    count+=1
newimg=Image.new(img.mode,img.size)
newimg.putdata(new_pixels)
newimg.save('./new_img1.bmp')

