# Landray EKP OA system allows bypass file extension blacklist and upload svg/shtml/mht files that can lead to Stored XSS, or phishing attack.

## What is Landray EKP?

Landray EKP is one of a series of OA-system products of Landray company.
It is used by many large and medium-sized enterprises in China.

![](pic/landray-ekp-1.jpg)
![](pic/landray-ekp-2.jpg)

## Vulnerability Type:
Stored XSS <br>
File uploade

## Vulnerability Version:
Landrary EKP V12.0.9.R.20160325
![](pic/landray-ekp-3.png)
![](pic/landray-ekp-4.jpg)

## Vulnerability Description AND recurrence:

### step 1

Login the EKP OA system, then click the menu to go into a working process creating page.

![](pic/landray-ekp-5.png)

### step 2

In the working process creating page, I can upload attachments. I try to upload `jsp`、`html` files at first, but I failed. Because there is a security check with a file extension blacklist in both frontend and backend. Just as screenshot shown as below:

![](pic/landray-ekp-6.png)

But, the file extensions `.svg`、`.shtml`、`mht` are not in the blacklist. So I try to upload `svg/shtml/mht` files to lead to stored xss, and I make it.

![](pic/landray-ekp-7.png)
![](pic/landray-ekp-8.jpg)
![](pic/landray-ekp-9.png)
![](pic/landray-ekp-10.png)

After I upload, I save and submit the working process, and then, I click the menu to pass the working process to another user to read.

![](pic/landray-ekp-11.png)
![](pic/landray-ekp-12.png)

### step 3

Login another user who mentioned above, and you can see there is a new message waiting to be read in the right side of the home page.

![](pic/landray-ekp-13.jpg)

Click the link and go to read the new message, then click the `.svg` file link to preview. Oh, this user is attacked by stored xss!

![](pic/landray-ekp-14.png)
![](pic/landray-ekp-15.png)

In the same way, uploading the `shtml` or `mht` file can lead to the same attacking, but the `shtml` or `mht` files only can be parsed and triggered XSS in IE browser.

![](pic/landray-ekp-16.png)
![](pic/landray-ekp-17.png)






## Vulnerability Impact

It allows bypass file extension blacklist and upload `svg`、`shtml`、`mht` files that can lead to Stored XSS, or phishing attack.